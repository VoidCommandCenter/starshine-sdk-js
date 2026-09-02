import amqp, { type ChannelModel } from "amqplib";

import type { RelayConfig } from "./config.js";
import { IdempotencyConflictError, type DurableOutbox } from "./outbox.js";
import { parseRelayEvent } from "./schema.js";

export async function startAmqpConsumer(
  config: RelayConfig,
  outbox: DurableOutbox,
): Promise<ChannelModel | undefined> {
  if (!config.amqpUrl || !config.amqpQueue) return undefined;
  const connection = await amqp.connect(config.amqpUrl);
  const channel = await connection.createChannel();
  await channel.assertQueue(config.amqpQueue, { durable: true });
  await channel.prefetch(config.amqpPrefetch);
  await channel.consume(config.amqpQueue, async (message) => {
    if (!message) return;
    let envelope;
    try {
      envelope = parseRelayEvent(JSON.parse(message.content.toString("utf8")) as unknown);
    } catch (error) {
      console.error(JSON.stringify({ level: "error", message: "rejecting invalid AMQP event", error: String(error) }));
      channel.nack(message, false, false);
      return;
    }
    try {
      await outbox.enqueue(envelope);
      channel.ack(message);
    } catch (error) {
      console.error(JSON.stringify({ level: "error", message: "AMQP enqueue failed", error: String(error) }));
      channel.nack(message, false, !(error instanceof IdempotencyConflictError));
    }
  });
  return connection;
}
