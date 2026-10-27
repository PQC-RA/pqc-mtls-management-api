import { getNodeAutoInstrumentations } from "@opentelemetry/auto-instrumentations-node";
import { PrometheusExporter } from "@opentelemetry/exporter-prometheus";
import { ExpressInstrumentation } from "@opentelemetry/instrumentation-express";
import { HttpInstrumentation } from "@opentelemetry/instrumentation-http";
import { NodeSDK } from "@opentelemetry/sdk-node";

// Automatically initializes OpenTelemetry before the application boots
// Prometheus metrics are exposed on a separate server at http://<host>:3001/metrics
const otelSDK = new NodeSDK({
	// host explicit: exporter-prometheus 0.300+ defaults to localhost only.
	metricReaders: [
		new PrometheusExporter({
			host: process.env.METRICS_HOST ?? "0.0.0.0",
			port: 3001,
		}),
	],
	instrumentations: [
		getNodeAutoInstrumentations(),
		new HttpInstrumentation(),
		new ExpressInstrumentation(),
	],
});

export default otelSDK;
