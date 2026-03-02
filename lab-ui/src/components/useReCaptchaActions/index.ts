"use client";

import {
  useCheckboxClickHandler,
  useVerifyHandler,
  useRefreshHandler,
  useSolutionChangeHandler,
  useExpireHandler,
} from "./handlers";
import type { ReCaptchaActions, ReCaptchaActionDeps } from "./types";

export function useReCaptchaActions(deps: ReCaptchaActionDeps): ReCaptchaActions {
  const { captchaState, startTimeRef, recordEvent } = deps;

  const handleCheckboxClick = useCheckboxClickHandler({
    events: captchaState.events,
    recordEvent,
    startTimeRef,
    captchaState,
  });

  const handleVerify = useVerifyHandler({
    sessionId: captchaState.sessionId,
    solution: captchaState.solution,
    events: captchaState.events,
    startTimeRef,
    setState: captchaState.setState,
    setError: captchaState.setError,
    setBehavioralMetrics: captchaState.setBehavioralMetrics,
    setToken: captchaState.setToken,
    setTokenExpiry: captchaState.setTokenExpiry,
  });

  const handleRefresh = useRefreshHandler({
    sessionId: captchaState.sessionId,
    recordEvent,
    setError: captchaState.setError,
    setSolution: captchaState.setSolution,
    setChallenge: captchaState.setChallenge,
    setRefreshesRemaining: captchaState.setRefreshesRemaining,
  });

  const handleSolutionChange = useSolutionChangeHandler({ setSolution: captchaState.setSolution });

  const handleExpire = useExpireHandler({
    setToken: captchaState.setToken,
    setTokenExpiry: captchaState.setTokenExpiry,
    setState: captchaState.setState,
  });

  return {
    handleCheckboxClick,
    handleVerify,
    handleRefresh,
    handleSolutionChange,
    handleExpire,
  };
}

export type { ReCaptchaActions, ReCaptchaState, WidgetState } from "./types";
