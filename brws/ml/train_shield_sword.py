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
    def __init__(self, target_api="http://localhost:8080/api/ml/evaluate"):
        self.target_api = target_api
        
        # State: 14 dimensions
        # [0]  Webdriver    [1]  Canvas       [2]  ClientHints   [3]  Isomorphic
        # [4]  Hardware     [5]  Network      [6]  Plugins       [7]  Geometry
        # [8]  Video        [9]  Permissions  [10] Timezone
        # [11] CaptchaPresented [12] CaptchaSolved [13] CaptchaDifficulty
        self.state = [1.0] * 11 + [0.0, 0.0, 0.0]
        
        self.action_space = 14
        self.observation_space = 14
        
        self.fsm_config = {
            "Enabled": True,
            "RemoveWebDriver": False,
            "CanvasNoise": False,
            "ClientHints": False,
            "RandomUserAgent": False,
            "WebGLSpoof": False,
            "HardwareSync": False,
            "NetworkSync": False,
            "PluginsSync": False,
            "GeometrySync": False,
            "VideoSync": False,
            "PermissionsSync": False,
            "TimezoneSync": False,
            "CaptchaSolver": False,
            "HumanizeInteraction": False,
            "DelayedNavigation": False
        }

    def reset(self):
        self.state = [1.0] * 11 + [0.0, 0.0, 0.0]
        for k in self.fsm_config:
            if k != "Enabled":
                self.fsm_config[k] = False
        return torch.tensor(self.state, dtype=torch.float32)

    def step(self, action):
        # Action mappings: 0-10 = fingerprint evasion, 11-13 = CAPTCHA specific
        actions_map = {
            0: "RemoveWebDriver",
            1: "CanvasNoise",
            2: "ClientHints",
            3: "RandomUserAgent",
            4: "HardwareSync",
            5: "NetworkSync",
            6: "PluginsSync",
            7: "GeometrySync",
            8: "VideoSync",
            9: "PermissionsSync",
            10: "TimezoneSync",
            11: "CaptchaSolver",
            12: "HumanizeInteraction",
            13: "DelayedNavigation"
        }
        
        if action in actions_map:
            key = actions_map[action]
            if not self.fsm_config[key]:
                self.fsm_config[key] = True

        payload = {
            "fsm_config": self.fsm_config,
            "target_url": "http://localhost:8080/api/ml/trap"
        }
        
        try:
            resp = requests.post(self.target_api, json=payload, timeout=15)
            result = resp.json()
            
            if not result.get("success"):
                return torch.tensor(self.state, dtype=torch.float32), -10.0, True
                
            bot_score = result.get("bot_score", 1.0)
            is_bot = result.get("is_bot", True)
            anomalies = result.get("anomalies", [])
            captcha_presented = result.get("captcha_presented", False)
            captcha_solved = result.get("captcha_solved", False)
            captcha_type = result.get("captcha_type", "")
            
            # Update 11-dim fingerprint state from anomalies
            self.state = [0.0] * 14
            for a in anomalies:
                a_lower = a.lower()
                if "webdriver" in a_lower: self.state[0] = 1.0
                if "canvas" in a_lower or "webgl" in a_lower: self.state[1] = 1.0
                if "client_hints" in a_lower or "inconsistent_ch" in a_lower: self.state[2] = 1.0
                if "mismatch" in a_lower and "timezone" not in a_lower: self.state[3] = 1.0
                if "hardware" in a_lower or "memory" in a_lower: self.state[4] = 1.0
                if "network" in a_lower: self.state[5] = 1.0
                if "plugins" in a_lower: self.state[6] = 1.0
                if "geometry" in a_lower: self.state[7] = 1.0
                if "video" in a_lower: self.state[8] = 1.0
                if "permissions" in a_lower: self.state[9] = 1.0
                if "timezone" in a_lower: self.state[10] = 1.0
            
            # CAPTCHA dimensions
            self.state[11] = 1.0 if captcha_presented else 0.0
            self.state[12] = 1.0 if captcha_solved else 0.0
            # Difficulty: 0=none, 0.5=text, 1.0=hcaptcha
            if captcha_type == "text":
                self.state[13] = 0.5
            elif captcha_type in ("hcaptcha", "recaptcha"):
                self.state[13] = 1.0
            else:
                self.state[13] = 0.0
            
            # Reward shaping with CAPTCHA awareness
            reward = 0.0
            
            if bot_score < 0.1 and not captcha_presented:
                # Perfect evasion — no CAPTCHA, clean pass
                reward = 100.0
                done = True
            elif captcha_presented and captcha_solved:
                # CAPTCHA was issued but we solved it — good!
                reward = 50.0
                done = True
            elif captcha_presented and not captcha_solved:
                # CAPTCHA was issued and we FAILED — bad
                reward = -20.0
                done = False
            elif is_bot:
                # Hard blocked — worst outcome
                reward = -bot_score * 15.0
                done = False
            else:
                # Partially detected — bad but recoverable
                reward = -bot_score * 10.0
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
    batch_size = 16

    memory = deque(maxlen=5000)
    model = DQNAgent(env.observation_space, env.action_space)
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.MSELoss()

    best_reward = float('-inf')
    captcha_stats = {"presented": 0, "solved": 0, "failed": 0}

    print("--- Initiating Phase 17 DQN Training (Shield+CAPTCHA vs Sword) ---\n")

    for e in range(episodes):
        state = env.reset()
        state = state.unsqueeze(0)
        
        total_reward = 0
        captcha_this_ep = False
        captcha_solved_this_ep = False
        
        for time_step in range(25): 
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
            
            # Track CAPTCHA stats
            if state[0][11].item() > 0:
                captcha_this_ep = True
                if state[0][12].item() > 0:
                    captcha_solved_this_ep = True
            
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
        
        # Update CAPTCHA stats
        if captcha_this_ep:
            captcha_stats["presented"] += 1
            if captcha_solved_this_ep:
                captcha_stats["solved"] += 1
            else:
                captcha_stats["failed"] += 1
        
        if total_reward > best_reward:
            best_reward = total_reward
            
        if done or time_step == 24:
            captcha_flag = ""
            if captcha_this_ep:
                captcha_flag = f" | CAPTCHA: {'SOLVED' if captcha_solved_this_ep else 'FAILED'}"
            print(f"Episode: {e+1:2d}/{episodes} | Steps: {time_step+1} | "
                  f"Reward: {total_reward:7.1f} | Explore: {epsilon:.2f} | "
                  f"Best: {best_reward:7.1f}{captcha_flag}")

    print(f"\n--- Phase 17 Training Complete ---")
    print(f"CAPTCHA Stats: {captcha_stats['presented']} presented, "
          f"{captcha_stats['solved']} solved, {captcha_stats['failed']} failed")
    
    import os
    os.makedirs("models", exist_ok=True)
    torch.save(model.state_dict(), "models/shield_sword_policy.pt")
    print("Optimal live-validated evasion policy saved to models/shield_sword_policy.pt")

if __name__ == "__main__":
    train_live_agent()
