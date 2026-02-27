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
# States are observed anomalies: [webdriver_exposed, canvas_static, ja4_banned, typing_static]
# The goal is to reach [0, 0, 0, 0] (A totally organic stealth fingerprint)
class StealthWAFEnv:
    def __init__(self):
        self.state = [1.0, 1.0, 1.0, 1.0] # Initial bot: everything is suspicious
        # Actions:
        # 0: Toggle Webdriver Spoofing
        # 1: Toggle Canvas Randomization
        # 2: Reroll TLS JA4 Fingerprint
        # 3: Inject FSM Human Typing Timing
        self.action_space = 4
        self.observation_space = 4
        
    def reset(self):
        # Start a new request completely detected
        self.state = [1.0, 1.0, 1.0, 1.0]
        return torch.tensor(self.state, dtype=torch.float32)

    def step(self, action):
        # Apply the FSM toggle based on the agent's decision
        if action == 0 and self.state[0] == 1.0:
            self.state[0] = 0.0 # Successfully spoofed webdriver
        elif action == 1 and self.state[1] == 1.0:
            self.state[1] = 0.0 # Successfully randomized canvas
        elif action == 2 and self.state[2] == 1.0:
            self.state[2] = 0.0 # Successfully evaded banned TLS JA4
        elif action == 3 and self.state[3] == 1.0:
            self.state[3] = 0.0 # Successfully added human timing variance
            
        # Calculate Reward
        # WAF Logic: If any flag is 1.0, the bot is blocked (HTTP 403)
        is_blocked = sum(self.state) > 0
        
        if not is_blocked:
            reward = 100.0 # Bypassed!
            done = True
        else:
            reward = -1.0 # Still blocked, small penalty for taking time
            done = False
            
        return torch.tensor(self.state, dtype=torch.float32), reward, done

# -------------------------------------------------------------
# 2. PyTorch DQN Model Architecture 
# -------------------------------------------------------------
class DQNAgent(nn.Module):
    def __init__(self, input_dim, output_dim):
        super(DQNAgent, self).__init__()
        # A lightweight Multi-Layer Perceptron to evaluate FSM States
        self.fc1 = nn.Linear(input_dim, 24)
        self.fc2 = nn.Linear(24, 24)
        self.fc3 = nn.Linear(24, output_dim)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        return self.fc3(x)

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
    
    # Demonstrate the trained model
    print("\n[+] Testing Trained DQN Agent against fresh WAF Block...")
    state = env.reset().unsqueeze(0)
    print(f"Initial WAF Trace State: {state[0].tolist()} (Bot Detected)")
    while True:
        with torch.no_grad():
            q_values = model(state)
            action = torch.argmax(q_values[0]).item()
            
        action_names = ["Toggle Webdriver", "Toggle Canvas", "Reroll JA4", "Inject Timing"]
        print(f"-> Agent decides to: {action_names[action]}")
        
        state, reward, done = env.step(action)
        state = state.unsqueeze(0)
        
        if done:
            print(f"Final WAF Trace State: {state[0].tolist()} (HTTP 200 OK - Bypassed!)")
            break

if __name__ == "__main__":
    train_fsm_agent()
