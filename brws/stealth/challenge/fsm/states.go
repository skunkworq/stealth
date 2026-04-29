package fsm

import (
	"github.com/skunkworq/stealth/brws/core/instrumentation"
)

// ChallengeStates defines the generic states shared by all challenge solvers.
var ChallengeStates = struct {
	Idle         instrumentation.State
	Detecting    instrumentation.State
	Initializing instrumentation.State
	Solving      instrumentation.State
	Submitting   instrumentation.State
	Verifying    instrumentation.State
	Retrying     instrumentation.State
	Escalating   instrumentation.State
	Solved       instrumentation.State
	Failed       instrumentation.State
}{
	Idle:         "ch_idle",
	Detecting:    "ch_detecting",
	Initializing: "ch_initializing",
	Solving:      "ch_solving",
	Submitting:   "ch_submitting",
	Verifying:    "ch_verifying",
	Retrying:     "ch_retrying",
	Escalating:   "ch_escalating",
	Solved:       "ch_solved",
	Failed:       "ch_failed",
}

// ChallengeEvents defines the generic events shared by all challenge solvers.
var ChallengeEvents = struct {
	Detect   instrumentation.Event
	Init     instrumentation.Event
	Solve    instrumentation.Event
	Submit   instrumentation.Event
	Verify   instrumentation.Event
	Retry    instrumentation.Event
	Escalate instrumentation.Event
	Success  instrumentation.Event
	Fail     instrumentation.Event
}{
	Detect:   "ch_detect",
	Init:     "ch_init",
	Solve:    "ch_solve",
	Submit:   "ch_submit",
	Verify:   "ch_verify",
	Retry:    "ch_retry",
	Escalate: "ch_escalate",
	Success:  "ch_success",
	Fail:     "ch_fail",
}

// CloudflareSubStates defines sub-states inside the Solving state for Cloudflare.
var CloudflareSubStates = struct {
	SolvingPoW         instrumentation.State
	GeneratingFP       instrumentation.State
	GeneratingBehavior instrumentation.State
	WaitingHumanDelay  instrumentation.State
}{
	SolvingPoW:         "cf_solving_pow",
	GeneratingFP:       "cf_generating_fp",
	GeneratingBehavior: "cf_generating_behavior",
	WaitingHumanDelay:  "cf_waiting_human_delay",
}

// CloudflareSubEvents defines events for Cloudflare sub-state transitions.
var CloudflareSubEvents = struct {
	PoWSolved         instrumentation.Event
	FPGenerated       instrumentation.Event
	BehaviorGenerated instrumentation.Event
	DelayComplete     instrumentation.Event
}{
	PoWSolved:         "cf_pow_solved",
	FPGenerated:       "cf_fp_generated",
	BehaviorGenerated: "cf_behavior_generated",
	DelayComplete:     "cf_delay_complete",
}

// DataDomeSubStates defines sub-states inside the Solving state for DataDome.
var DataDomeSubStates = struct {
	SolvingSlider       instrumentation.State
	GeneratingSignals   instrumentation.State
	SolvingInnerCaptcha instrumentation.State
	SettingCookie       instrumentation.State
}{
	SolvingSlider:       "dd_solving_slider",
	GeneratingSignals:   "dd_generating_signals",
	SolvingInnerCaptcha: "dd_solving_inner_captcha",
	SettingCookie:       "dd_setting_cookie",
}

// DataDomeSubEvents defines events for DataDome sub-state transitions.
var DataDomeSubEvents = struct {
	SliderSolved     instrumentation.Event
	SignalsGenerated instrumentation.Event
	InnerSolved      instrumentation.Event
	CookieSet        instrumentation.Event
}{
	SliderSolved:     "dd_slider_solved",
	SignalsGenerated: "dd_signals_generated",
	InnerSolved:      "dd_inner_solved",
	CookieSet:        "dd_cookie_set",
}

// NewChallengeFSM creates a base FSM with generic challenge states and transitions.
// Provider-specific solvers add their own sub-states via fsm.AddState().
func NewChallengeFSM(name string) *instrumentation.FSM {
	fsm := instrumentation.NewFSM(name, ChallengeStates.Idle)

	fsm.AddState(&instrumentation.StateConfig{
		State: ChallengeStates.Idle,
		Name:  "Idle",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			ChallengeEvents.Detect: ChallengeStates.Detecting,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: ChallengeStates.Detecting,
		Name:  "Detecting",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			ChallengeEvents.Init: ChallengeStates.Initializing,
			ChallengeEvents.Fail: ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: ChallengeStates.Initializing,
		Name:  "Initializing",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			ChallengeEvents.Solve: ChallengeStates.Solving,
			ChallengeEvents.Fail:  ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: ChallengeStates.Solving,
		Name:  "Solving",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			ChallengeEvents.Submit:   ChallengeStates.Submitting,
			ChallengeEvents.Retry:    ChallengeStates.Retrying,
			ChallengeEvents.Escalate: ChallengeStates.Escalating,
			ChallengeEvents.Fail:     ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: ChallengeStates.Submitting,
		Name:  "Submitting",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			ChallengeEvents.Verify: ChallengeStates.Verifying,
			ChallengeEvents.Retry:  ChallengeStates.Retrying,
			ChallengeEvents.Fail:   ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: ChallengeStates.Verifying,
		Name:  "Verifying",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			ChallengeEvents.Success: ChallengeStates.Solved,
			ChallengeEvents.Retry:   ChallengeStates.Retrying,
			ChallengeEvents.Fail:    ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: ChallengeStates.Retrying,
		Name:  "Retrying",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			ChallengeEvents.Solve:    ChallengeStates.Solving,
			ChallengeEvents.Escalate: ChallengeStates.Escalating,
			ChallengeEvents.Fail:     ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: ChallengeStates.Escalating,
		Name:  "Escalating",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			ChallengeEvents.Init: ChallengeStates.Initializing,
			ChallengeEvents.Fail: ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State:         ChallengeStates.Solved,
		Name:          "Solved",
		TransitionMap: map[instrumentation.Event]instrumentation.State{},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State:         ChallengeStates.Failed,
		Name:          "Failed",
		TransitionMap: map[instrumentation.Event]instrumentation.State{},
	})

	return fsm
}

// NewCloudflareFSM creates an FSM with Cloudflare-specific sub-states.
func NewCloudflareFSM() *instrumentation.FSM {
	fsm := NewChallengeFSM("cloudflare-challenge")

	fsm.AddState(&instrumentation.StateConfig{
		State: CloudflareSubStates.SolvingPoW,
		Name:  "SolvingPoW",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			CloudflareSubEvents.PoWSolved: CloudflareSubStates.GeneratingFP,
			ChallengeEvents.Fail:          ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: CloudflareSubStates.GeneratingFP,
		Name:  "GeneratingFingerprint",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			CloudflareSubEvents.FPGenerated: CloudflareSubStates.GeneratingBehavior,
			ChallengeEvents.Submit:          ChallengeStates.Submitting,
			ChallengeEvents.Fail:            ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: CloudflareSubStates.GeneratingBehavior,
		Name:  "GeneratingBehavior",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			CloudflareSubEvents.BehaviorGenerated: CloudflareSubStates.WaitingHumanDelay,
			ChallengeEvents.Fail:                  ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: CloudflareSubStates.WaitingHumanDelay,
		Name:  "WaitingHumanDelay",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			CloudflareSubEvents.DelayComplete: ChallengeStates.Submitting,
			ChallengeEvents.Fail:              ChallengeStates.Failed,
		},
	})

	return fsm
}

// NewDataDomeFSM creates an FSM with DataDome-specific sub-states.
func NewDataDomeFSM() *instrumentation.FSM {
	fsm := NewChallengeFSM("datadome-challenge")

	fsm.AddState(&instrumentation.StateConfig{
		State: DataDomeSubStates.SolvingSlider,
		Name:  "SolvingSlider",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			DataDomeSubEvents.SliderSolved: DataDomeSubStates.GeneratingSignals,
			ChallengeEvents.Escalate:       DataDomeSubStates.SolvingInnerCaptcha,
			ChallengeEvents.Fail:           ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: DataDomeSubStates.GeneratingSignals,
		Name:  "GeneratingSignals",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			DataDomeSubEvents.SignalsGenerated: ChallengeStates.Submitting,
			ChallengeEvents.Fail:               ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: DataDomeSubStates.SolvingInnerCaptcha,
		Name:  "SolvingInnerCaptcha",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			DataDomeSubEvents.InnerSolved: DataDomeSubStates.SettingCookie,
			ChallengeEvents.Fail:          ChallengeStates.Failed,
		},
	})

	fsm.AddState(&instrumentation.StateConfig{
		State: DataDomeSubStates.SettingCookie,
		Name:  "SettingCookie",
		TransitionMap: map[instrumentation.Event]instrumentation.State{
			DataDomeSubEvents.CookieSet: ChallengeStates.Verifying,
			ChallengeEvents.Fail:        ChallengeStates.Failed,
		},
	})

	return fsm
}
