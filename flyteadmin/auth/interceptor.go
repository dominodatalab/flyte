package auth

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/flyteorg/flyte/flytestdlib/logger"
)

func BlanketAuthorization(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (
	resp interface{}, err error) {

	identityContext := IdentityContextFromContext(ctx)
	if identityContext.IsEmpty() {
		return handler(ctx, req)
	}

	if !identityContext.Scopes().Has(ScopeAll) {
		s := "authenticated user doesn't have required scope"
		logger.Debugf(ctx, "dump %s", s)
		logger.Debugf(ctx, "authenticated user doesn't have required scope")
		s += fmt.Sprintf(" // authenticated user has %d scopes", identityContext.Scopes().Len())
		logger.Debugf(ctx, "dump %s", s)
		s += fmt.Sprintf(" // dump %s %s %s %s %s %s", identityContext.appID, identityContext.audience, identityContext.executionIdentity,
			identityContext.userID, identityContext.userInfo.Name, identityContext.userInfo.Subject)
		logger.Debugf(ctx, "dump %s", s)
		for key := range identityContext.Scopes() {
			logger.Debugf(ctx, "authenticated user has the scope %s", key)
			s += fmt.Sprintf(" // authenticated user has the scope %s", key)
		}
		return nil, status.Errorf(codes.Unauthenticated, s)
	}

	return handler(ctx, req)
}

// ExecutionUserIdentifierInterceptor injects identityContext.UserID() to identityContext.executionIdentity
func ExecutionUserIdentifierInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (
	resp interface{}, err error) {
	identityContext := IdentityContextFromContext(ctx)
	identityContext = identityContext.WithExecutionUserIdentifier(identityContext.UserID())
	ctx = identityContext.WithContext(ctx)
	return handler(ctx, req)
}
