import json
import os
import random
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from collections import deque

# -------------------------------------------------------------
# 1. Environment Simulation (Mimicking brws/adversarial/stealth_detector.go)
# -------------------------------------------------------------
# 18-dimensional state space matching the live Go proxy environment:
# [0]  Webdriver    [1]  Canvas       [2]  ClientHints   [3]  Isomorphic
# [4]  Hardware     [5]  Network      [6]  Plugins       [7]  Geometry
# [8]  Video        [9]  Permissions  [10] Timezone
# [11] CaptchaPresented [12] CaptchaSolved [13] CaptchaDifficulty
# [14] MouseVelocity [15] TypingSpeed [16] Straightness [17] SolveTime
class StealthWAFEnv:
    def __init__(self):
        # Initial bot: all fingerprint dimensions suspicious, behavioral/captcha zeroed
        self.state = [1.0] * 11 + [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        # 18 actions matching the full stealth config action space
        self.action_space = 18
        self.observation_space = 18

        # Action mappings
        self.actions_map = {
            0: "RemoveWebDriver",
            1: "CanvasNoise",
            2: "ClientHints",
            3: "RandomUserAgent",
            4: "WebGLSpoof",
            5: "HardwareSync",
            6: "NetworkSync",
            7: "PluginsSync",
            8: "GeometrySync",
            9: "VideoSync",
            10: "PermissionsSync",
            11: "TimezoneSync",
            12: "CaptchaSolver",
            13: "HumanizeInteraction",
            14: "DelayedNavigation",
            15: "WebRTCDisable",
            16: "CanvasNoiseStrength",
            17: "HeadlessPatches",
        }

    def reset(self):
        # Start a new request completely detected
        self.state = [1.0] * 11 + [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        return torch.tensor(self.state, dtype=torch.float32)

    def step(self, action):
        # Actions 0-10: fingerprint evasion toggles (clear the corresponding detection flag)
        if 0 <= action <= 10 and self.state[action] == 1.0:
            self.state[action] = 0.0

        # Actions 11-13: CAPTCHA-related
        elif action == 12:
            # CaptchaSolver: if captcha presented, attempt solve
            if self.state[11] > 0:
                self.state[12] = 1.0  # Mark solved
                self.state[17] = random.uniform(0.1, 0.5)  # Solve time normalized
        elif action == 13:
            # HumanizeInteraction: improve behavioral signals
            self.state[14] = random.uniform(0.3, 0.8)  # Mouse velocity
            self.state[15] = random.uniform(0.3, 0.7)  # Typing speed
            self.state[16] = random.uniform(0.5, 0.9)  # Straightness (higher = more human)

        # Actions 14-17: advanced behavioral toggles
        elif action == 14:
            # DelayedNavigation: adds human-like delay patterns
            self.state[14] = max(self.state[14], random.uniform(0.2, 0.6))
        elif action == 15:
            # WebRTCDisable: clears network-related detection
            self.state[5] = 0.0  # Network dimension
        elif action == 16:
            # CanvasNoiseStrength: fine-tune canvas noise
            self.state[1] = 0.0  # Clear canvas detection
        elif action == 17:
            # HeadlessPatches: clears webdriver and hardware flags
            self.state[0] = 0.0  # Webdriver
            self.state[4] = 0.0  # Hardware

        # Calculate Reward: fingerprint dimensions [0-10] must all be zero
        fingerprint_score = sum(self.state[:11])
        is_blocked = fingerprint_score > 0

        if not is_blocked:
            reward = 100.0  # Bypassed!
            done = True
        else:
            reward = -1.0  # Still blocked, small penalty for taking time
            done = False

        return torch.tensor(self.state, dtype=torch.float32), reward, done

# -------------------------------------------------------------
# 2. PyTorch DQN Model Architecture (4-layer, matches Go PolicyLoader)
# -------------------------------------------------------------
class DQNAgent(nn.Module):
    def __init__(self, input_dim, output_dim):
        super(DQNAgent, self).__init__()
        self.fc1 = nn.Linear(input_dim, 64)
        self.fc2 = nn.Linear(64, 64)
        self.fc3 = nn.Linear(64, 32)
        self.fc4 = nn.Linear(32, output_dim)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = F.relu(self.fc3(x))
        return self.fc4(x)

# -------------------------------------------------------------
# 3. Training Loop (Q-Learning)
# -------------------------------------------------------------
def train_fsm_agent():
    env = StealthWAFEnv()
    
    # Hyperparameters
    episodes = 500
    gamma = 0.95        # discount rate
    epsilon = 1.0       # exploration rate
    epsilon_min = 0.01
    epsilon_decay = 0.995
    learning_rate = 0.001
    batch_size = 32

    # Memory Replay Buffer
    memory = deque(maxlen=2000)

    # Initialize Model
    model = DQNAgent(env.observation_space, env.action_space)
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.MSELoss()

    print("--- Initiating PyTorch Reinforcement Learning for FSM Evasiom ---\n")

    for e in range(episodes):
        state = env.reset()
        state = state.unsqueeze(0) # Add batch dimension
        
        total_reward = 0
        for time_step in range(10): # Max 10 mutations per HTTP Request
            
            # 1. Choose FSM Action (Epsilon-Greedy policy)
            if random.random() <= epsilon:
                action = random.randrange(env.action_space)
            else:
                with torch.no_grad():
                    q_values = model(state)
                    action = torch.argmax(q_values[0]).item()
                    
            # 2. Execute Action against WAF Environment
            next_state, reward, done = env.step(action)
            next_state = next_state.unsqueeze(0)
            
            total_reward += reward
            
            # 3. Remember the Trace iteration
            memory.append((state, action, reward, next_state, done))
            state = next_state
            
            # 4. Train the Neural Network via Replay Buffer
            if len(memory) > batch_size:
                minibatch = random.sample(memory, batch_size)
                
                # Unpack transitions
                states = torch.cat([transition[0] for transition in minibatch])
                actions = torch.tensor([transition[1] for transition in minibatch])
                rewards = torch.tensor([transition[2] for transition in minibatch], dtype=torch.float32)
                next_states = torch.cat([transition[3] for transition in minibatch])
                dones = torch.tensor([transition[4] for transition in minibatch], dtype=torch.float32)

                # Q-learning Target calculation
                current_q = model(states).gather(1, actions.unsqueeze(1)).squeeze(1)
                
                with torch.no_grad():
                    max_next_q = model(next_states).max(1)[0]
                    target_q = rewards + (gamma * max_next_q * (1 - dones))

                loss = criterion(current_q, target_q)
                
                # Backpropagation
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()

            if done:
                break
                
        # Decay exploration rate
        if epsilon > epsilon_min:
            epsilon *= epsilon_decay
            
        # Log progress every 50 episodes
        if (e + 1) % 50 == 0:
            print(f"Episode: {e+1:3d}/{episodes} | FSM Mutations Taken: {time_step+1} | "
                  f"Total Reward: {total_reward:5.1f} | Epsilon (Exploration): {epsilon:.3f}")

    print("\n--- Training Complete ---")
    
    # Save the trained ML model exactly as proposed in architecture (.pt can later be ONNX)
    os.makedirs("models", exist_ok=True)
    torch.save(model.state_dict(), "models/fsm_rl_policy.pt")
    print(f"Optimal Evasion Policy saved to models/fsm_rl_policy.pt")

    # Export weights as JSON for Go inference
    weights = {
        "w1": model.fc1.weight.detach().cpu().numpy().tolist(),
        "b1": model.fc1.bias.detach().cpu().numpy().tolist(),
        "w2": model.fc2.weight.detach().cpu().numpy().tolist(),
        "b2": model.fc2.bias.detach().cpu().numpy().tolist(),
        "w3": model.fc3.weight.detach().cpu().numpy().tolist(),
        "b3": model.fc3.bias.detach().cpu().numpy().tolist(),
        "w4": model.fc4.weight.detach().cpu().numpy().tolist(),
        "b4": model.fc4.bias.detach().cpu().numpy().tolist(),
    }
    with open("models/fsm_rl_weights.json", "w") as f:
        json.dump(weights, f)
    print("Go-compatible weights exported to models/fsm_rl_weights.json")

    # Demonstrate the trained model
    print("\n[+] Testing Trained DQN Agent against fresh WAF Block...")
    state = env.reset().unsqueeze(0)
    print(f"Initial WAF Trace State: {state[0].tolist()} (Bot Detected)")
    action_names = {v: v for v in env.actions_map.values()}
    for step in range(30):
        with torch.no_grad():
            q_values = model(state)
            action = torch.argmax(q_values[0]).item()

        name = env.actions_map.get(action, f"Action-{action}")
        print(f"-> Agent decides to: {name}")

        state, reward, done = env.step(action)
        state = state.unsqueeze(0)

        if done:
            print(f"Final WAF Trace State: {state[0].tolist()} (HTTP 200 OK - Bypassed!)")
            break

if __name__ == "__main__":
    train_fsm_agent()
