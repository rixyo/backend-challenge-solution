import { createClient } from "redis";

const redisClient = createClient({ url: process.env.REDIS_URL });

redisClient.on("error", (err) => {
  console.error("Redis error:", err);
});

const connectRedis = async () => {
  try {
    await redisClient.connect();
    console.log("Connected to Redis");
  } catch (error) {
    console.log("Failed to connect to Redis:", error);
    //process.exit(1); // Exit the process if Redis fails to connect
  }
};

connectRedis();

// Graceful shutdown
process.on("SIGINT", async () => {
  await redisClient.quit();
  console.log("Redis connection closed.");
  process.exit(0);
});

export { redisClient };
