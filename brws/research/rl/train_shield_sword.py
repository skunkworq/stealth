import argparse
import json
import os
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
    def __init__(self, target_api=None):
        self.target_api = target_api or os.environ.get(
            "LAB_URL", "http://localhost:8080/api/ml/evaluate"
        )
        
        # State: 18 dimensions
        # [0]  Webdriver    [1]  Canvas       [2]  ClientHints   [3]  Isomorphic
        # [4]  Hardware     [5]  Network      [6]  Plugins       [7]  Geometry
        # [8]  Video        [9]  Permissions  [10] Timezone
        # [11] CaptchaPresented [12] CaptchaSolved [13] CaptchaDifficulty
        # [14] MouseVelocity [15] TypingSpeed [16] Straightness [17] SolveTime
        self.state = [1.0] * 11 + [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

        self.action_space = 18
        self.observation_space = 18
        
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
            "DelayedNavigation": False,
            "WebRTCDisable": False,
            "CanvasNoiseStrength": False,
            "HeadlessPatches": False
        }

    def reset(self):
        self.state = [1.0] * 11 + [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        for k in self.fsm_config:
            if k != "Enabled":
                self.fsm_config[k] = False
        return torch.tensor(self.state, dtype=torch.float32)

    def step(self, action):
        # Action mappings: 0-11 = fingerprint evasion, 12-13 = CAPTCHA, 14-17 = behavioral
        actions_map = {
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
            self.state = [0.0] * 18
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

            # Behavioral dimensions [14-17]
            behavioral = result.get("behavioral", {})
            self.state[14] = min(behavioral.get("mouse_velocity", 0.0) / 2000.0, 1.0)
            self.state[15] = min(behavioral.get("typing_speed", 0.0) / 500.0, 1.0)
            self.state[16] = behavioral.get("straightness", 0.0)
            solve_time = result.get("solve_time_ms", 0)
            self.state[17] = min(solve_time / 30000.0, 1.0)

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
def train_live_agent(lab_url=None, num_episodes=50, model_dir="models"):
    env = LiveGoProxyEnv(target_api=lab_url)

    episodes = num_episodes
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

    os.makedirs(model_dir, exist_ok=True)

    pt_path = os.path.join(model_dir, "shield_sword_policy.pt")
    torch.save(model.state_dict(), pt_path)
    print(f"Optimal live-validated evasion policy saved to {pt_path}")

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
    weights_path = os.path.join(model_dir, "shield_sword_weights.json")
    with open(weights_path, "w") as f:
        json.dump(weights, f)
    print(f"Go-compatible weights exported to {weights_path}")

    # Export training report for Go CLI
    report = {
        "episodes": episodes,
        "best_reward": best_reward,
        "final_epsilon": epsilon,
        "captcha_stats": captcha_stats,
        "model_path": pt_path,
        "weights_path": weights_path,
    }
    report_path = os.path.join(model_dir, "training_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Training report exported to {report_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train DQN shield/sword agent")
    parser.add_argument("--lab-url", default=None, help="Lab evaluation API URL")
    parser.add_argument("--episodes", type=int, default=50, help="Number of training episodes")
    parser.add_argument("--model-dir", default="models", help="Model output directory")
    args = parser.parse_args()

    train_live_agent(
        lab_url=args.lab_url,
        num_episodes=args.episodes,
        model_dir=args.model_dir,
    )
