import otelSDK from "@/tracing";

otelSDK.start();

import { Logger, ValidationPipe } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { NestExpressApplication } from "@nestjs/platform-express";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";

import { AppModule } from "@/app.module";
import { HttpExceptionFilter } from "@/common/filters/http-exception.filter";

async function bootstrap() {
	// rawBody: true preserves the exact request bytes on req.rawBody alongside
	// the normal parsed body. Needed by EnrollHmacGuard, which must HMAC the
	// same bytes the gateway signed -- a re-serialized JSON.stringify(body)
	// would not reliably match (key order/whitespace).
	const app = await NestFactory.create<NestExpressApplication>(AppModule, {
		rawBody: true,
	});
	const logger = new Logger("Bootstrap");

	// Lock CORS to an explicit allowlist.  Set CORS_ALLOWED_ORIGINS to a
	// comma-separated list of permitted origins (e.g. "https://admin.example.com").
	// When the variable is absent all cross-origin browser requests are blocked,
	// which is correct for a gateway management API accessed over mTLS.
	const corsOrigins = process.env.CORS_ALLOWED_ORIGINS
		? process.env.CORS_ALLOWED_ORIGINS.split(",")
				.map(o => o.trim())
				.filter(Boolean)
		: false;
	app.enableCors({
		origin: corsOrigins,
		allowedHeaders: ["Content-Type", "Authorization"],
		methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
		credentials: false,
	});

	app.useGlobalPipes(
		new ValidationPipe({
			whitelist: true,
			forbidNonWhitelisted: true,
			transform: true,
		})
	);

	app.useGlobalFilters(new HttpExceptionFilter());

	const config = new DocumentBuilder()
		.setTitle("PQC-GW Management API")
		.setDescription(
			"The API description for Post-Quantum M2M API Gateway management.\n\n" +
				"**Auth**: All admin endpoints require a gateway-signed RS256 JWT. " +
				"In production the PQC OpenResty gateway mints the JWT from the mTLS client certificate and injects it as `Authorization: Bearer <token>`. " +
				"For local testing, paste a valid JWT obtained from the gateway into the **Authorize** dialog."
		)
		.setVersion("1.0")
		.addTag("certs", "Certificate Lifecycle Management")
		.addTag(
			"cert-lookup",
			"Backend-facing certificate-by-fingerprint lookup (Token 2)"
		)
		.addTag("crl", "Certificate Revocation List Operations")
		.addTag("policy", "Routing and Policy Configurations")
		.addTag("audit", "Audit Logging and Monitoring")
		.addTag("identity", "Authenticated caller identity / privilege")
		.addTag("health", "System Health Checks")
		.addBearerAuth(
			{
				type: "http",
				scheme: "bearer",
				bearerFormat: "JWT",
				description:
					"RS256 JWT issued by the PQC OpenResty gateway. " +
					"Claims: sub (client CN), fpr (cert SHA-256 fingerprint), iat, exp (+60 s). " +
					"Authorization role (admin/auditor) is resolved server-side from `fpr`, not from a JWT claim.",
			},
			"GatewayJWT"
		)
		.addSecurityRequirements("GatewayJWT")
		.build();

	const documentFactory = () => SwaggerModule.createDocument(app, config);

	SwaggerModule.setup("api/docs", app, documentFactory);

	app.setGlobalPrefix("api");

	const port = Number(process.env.PORT ?? 3000);
	const host = process.env.HOST ?? "0.0.0.0";

	await app.listen(port, host);

	const baseUrl = await app.getUrl();
	logger.log(`Management API listening at ${baseUrl}/api`);
}

bootstrap();
