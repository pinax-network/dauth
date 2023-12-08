package server

import (
	"context"
	"github.com/streamingfast/dtracing"
	"github.com/streamingfast/logging"
	"go.uber.org/zap"
	"net/url"
	"regexp"

	"github.com/streamingfast/dauth"
	"github.com/streamingfast/dauth/middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var zlog, _ = logging.PackageLogger("dauth", "github.com/streamingfast/dauth/middleware/grpc")

var portSuffixRegex = regexp.MustCompile(`:[0-9]{2,5}$`)
var EmptyMetadata = metadata.New(nil)

type AuthenticatedServerStream struct {
	grpc.ServerStream
	AuthenticatedContext context.Context
}

func (s AuthenticatedServerStream) Context() context.Context {
	return s.AuthenticatedContext
}

func validateAuth(ctx context.Context, path string, authenticator dauth.Authenticator) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = EmptyMetadata
	}

	traceId := dtracing.GetTraceIDOrEmpty(ctx).String()
	zlog.Info("validate auth called", zap.String("trace_id", traceId))

	md["SF_TRACE_ID"] = []string{traceId}

	ctx, err := authenticator.Authenticate(ctx, path, url.Values(md), middleware.RealIP(peerFromContext(ctx), md))
	if err != nil {
		return ctx, err
	}
	return ctx, err
}
