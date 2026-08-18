import { getNodeAutoInstrumentations } from "@opentelemetry/auto-instrumentations-node";
import { PrometheusExporter } from "@opentelemetry/exporter-prometheus";
import { ExpressInstrumentation } from "@opentelemetry/instrumentation-express";
import { HttpInstrumentation } from "@opentelemetry/instrumentation-http";
import { NodeSDK } from "@opentelemetry/sdk-node";

// Automatically initializes OpenTelemetry before the application boots
// Prometheus metrics are exposed on a separate server at http://localhost:8081/metrics
const otelSDK = new NodeSDK({
	metricReader: new PrometheusExporter({ port: 3001 }),
	instrumentations: [
		getNodeAutoInstrumentations(),
		new HttpInstrumentation(),
		new ExpressInstrumentation(),
	],
});

export default otelSDK;
