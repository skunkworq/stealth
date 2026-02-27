import json
import random
import requests
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from collections import deque

# -------------------------------------------------------------
# 1. Live Go Proxy Environment (The Live Network Shield)
# -------------------------------------------------------------
class LiveGoProxyEnv:
    def __init__(self, target_api="http://localhost:8081/api/ml/evaluate"):
        self.target_api = target_api
        
        # State: [WebdriverDetected, CanvasAnomalous, ClientHintsMismatch, ExecutionMismatch]
        # We start with a highly detectable "Native Selenium" bot trace assumption.
        self.state = [1.0, 1.0, 1.0, 1.0] 
        
        # Actions:
        # 0: Remove WebDriver Stringification (Spoof Webdriver)
        # 1: Enable Canvas Noise Randomization (Spoof Canvas)
        # 2: Enable ClientHints Parity (Resolve Isomorphic ClientHints vs UA)
        # 3: Randomize User-Agent (Spoof Identity)
        self.action_space = 4
        self.observation_space = 4
        
        # Current applied FSM Configuration
        self.fsm_config = {
            "Enabled": True,
            "RemoveWebDriver": False,
            "CanvasNoise": False,
            "ClientHints": False,
            "RandomUserAgent": False,
            "WebGLSpoof": False
        }

    def reset(self):
        self.state = [1.0, 1.0, 1.0, 1.0]
        self.fsm_config = {
            "Enabled": True,
            "RemoveWebDriver": False,
            "CanvasNoise": False,
            "ClientHints": False,
            "RandomUserAgent": False,
            "WebGLSpoof": False
        }
        return torch.tensor(self.state, dtype=torch.float32)

    def step(self, action):
        # Apply the FSM toggle based on the agent's decision
        if action == 0 and not self.fsm_config["RemoveWebDriver"]:
            self.fsm_config["RemoveWebDriver"] = True
        elif action == 1 and not self.fsm_config["CanvasNoise"]:
            self.fsm_config["CanvasNoise"] = True
        elif action == 2 and not self.fsm_config["ClientHints"]:
            self.fsm_config["ClientHints"] = True
        elif action == 3 and not self.fsm_config["RandomUserAgent"]:
            self.fsm_config["RandomUserAgent"] = True
            
        # Send Live Evaluation to the Go Shield over network
        payload = {
            "fsm_config": self.fsm_config,
            "target_url": "http://localhost:8081/api/stealth-test"
        }
        
        try:
            resp = requests.post(self.target_api, json=payload, timeout=10)
            result = resp.json()
            
            if not result.get("success"):
                return torch.tensor(self.state, dtype=torch.float32), -10.0, True
                
            bot_score = result.get("bot_score", 1.0)
            is_bot = result.get("is_bot", True)
            anomalies = result.get("anomalies", [])
            
            # Map Live WAF Anomalies back to the RL State Space
            self.state = [0.0, 0.0, 0.0, 0.0]
            for a in anomalies:
                if "webdriver" in a.lower():
                    self.state[0] = 1.0
                if "canvas" in a.lower() or "webgl" in a.lower():
                    self.state[1] = 1.0
                if "client_hints" in a.lower() or "inconsistent_ch" in a.lower():
                    self.state[2] = 1.0
                if "mismatch" in a.lower(): # Frankenstein Isomorphic penalty
                    self.state[3] = 1.0
                    
            # Calculate Reward
            if not is_bot:
                reward = 100.0 # Bypassed the Live Proxy!
                done = True
            else:
                reward = -bot_score # Still blocked, penalty is proportional to how "bad" the WAF thinks we are
                done = False
                
            return torch.tensor(self.state, dtype=torch.float32), reward, done
            
        except Exception as e:
            print(f"Failed to communicate with Go API: {e}")
            return torch.tensor(self.state, dtype=torch.float32), -10.0, True

# -------------------------------------------------------------
# 2. PyTorch DQN Model Architecture (The Sword)
# -------------------------------------------------------------
class DQNAgent(nn.Module):
    def __init__(self, input_dim, output_dim):
        super(DQNAgent, self).__init__()
        self.fc1 = nn.Linear(input_dim, 24)
        self.fc2 = nn.Linear(24, 24)
        self.fc3 = nn.Linear(24, output_dim)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        return self.fc3(x)

# -------------------------------------------------------------
# 3. Live Training Loop (The Infinite Shield vs Sword)
# -------------------------------------------------------------
def train_live_agent():
    env = LiveGoProxyEnv()
    
    episodes = 50
    gamma = 0.95
    epsilon = 1.0
    epsilon_min = 0.01
    epsilon_decay = 0.95
    learning_rate = 0.001
    batch_size = 8

    memory = deque(maxlen=2000)
    model = DQNAgent(env.observation_space, env.action_space)
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.MSELoss()

    print("--- Initiating Deep Q-Network Live Proxy Training (The Loop) ---\n")

    for e in range(episodes):
        state = env.reset()
        state = state.unsqueeze(0)
        
        total_reward = 0
        for time_step in range(10): 
            # 1. Action Prediction
            if random.random() <= epsilon:
                action = random.randrange(env.action_space)
            else:
                with torch.no_grad():
                    q_values = model(state)
                    action = torch.argmax(q_values[0]).item()
                    
            # 2. Live Orchestration
            next_state, reward, done = env.step(action)
            next_state = next_state.unsqueeze(0)
            
            total_reward += reward
            memory.append((state, action, reward, next_state, done))
            state = next_state
            
            # 3. Model Weight Updates
            if len(memory) > batch_size:
                minibatch = random.sample(memory, batch_size)
                
                states = torch.cat([transition[0] for transition in minibatch])
                actions = torch.tensor([transition[1] for transition in minibatch])
                rewards = torch.tensor([transition[2] for transition in minibatch], dtype=torch.float32)
                next_states = torch.cat([transition[3] for transition in minibatch])
                dones = torch.tensor([transition[4] for transition in minibatch], dtype=torch.float32)

                current_q = model(states).gather(1, actions.unsqueeze(1)).squeeze(1)
                
                with torch.no_grad():
                    max_next_q = model(next_states).max(1)[0]
                    target_q = rewards + (gamma * max_next_q * (1 - dones))

                loss = criterion(current_q, target_q)
                
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()

            if done:
                break
                
        if epsilon > epsilon_min:
            epsilon *= epsilon_decay
            
        print(f"Episode: {e+1:2d}/{episodes} | Proxy Interactions: {time_step+1} | "
              f"Reward: {total_reward:5.1f} | Exploration: {epsilon:.2f} | End State: {state[0].tolist()}")

    print("\n--- Live Training Complete ---")
    torch.save(model.state_dict(), "models/shield_sword_policy.pt")
    print("Optimal live-validated evasion policy saved to models/shield_sword_policy.pt")

if __name__ == "__main__":
    train_live_agent()
