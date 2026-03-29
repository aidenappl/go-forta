package forta

import (
	"context"
	"strconv"
)

type contextKey string

const (
	ctxFortaID   contextKey = "forta-id"
	ctxFortaUser contextKey = "forta-user"
)

func contextWithFortaID(ctx context.Context, id int64) context.Context {
	return context.WithValue(ctx, ctxFortaID, id)
}

func contextWithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, ctxFortaUser, user)
}

func getFortaIDFromContext(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(ctxFortaID).(int64)
	return id, ok
}

func getUserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(ctxFortaUser).(*User)
	return u, ok
}

func userIDFromSub(sub string) (int64, error) {
	return strconv.ParseInt(sub, 10, 64)
}
