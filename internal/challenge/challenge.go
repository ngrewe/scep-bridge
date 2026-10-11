package challenge

import "log/slog"

type Challenge string
type ChallengeBytes []byte

func (c Challenge) LogValue() slog.Value      { return slog.StringValue("REDACTED") }
func (c ChallengeBytes) LogValue() slog.Value { return slog.StringValue("REDACTED") }
