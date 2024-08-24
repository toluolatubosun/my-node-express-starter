// set timezone
process.env.TZ = "Africa/Lagos";

import "express-async-errors";
import bcryptjs from "bcryptjs";
import mongoose from "mongoose";
import { createServer } from "http";
import express, { Express } from "express";

import routes from "@/routes";
import { CONFIGS } from "@/configs";
import { Server as SocketIO } from "socket.io";
import { redisClient } from "@/libraries/redis";
import { instrument } from "@socket.io/admin-ui";
import { connectMongoDB } from "@/libraries/mongodb";
import nodemailerInstance from "@/libraries/nodemailer";
import { createAdapter } from "@socket.io/mongo-adapter";
import SocketHandler from "@/services/socket-handler.service";
import { socketAuth } from "@/middlewares/socket-auth.middleware";
import { configureErrorMiddleware } from "@/middlewares/error.middleware";
import { configurePreRouteMiddleware } from "@/middlewares/pre-route.middleware";

const app: Express = express();
const httpServer = createServer(app);

// Socket IO Initialization
export const io = new SocketIO(httpServer, {
    cors: {
        credentials: true,
        origin: [...CONFIGS.CORS_ALLOWED_ORIGINS],
    },
});

// Socket IO Admin UI
instrument(io, {
    auth: {
        type: "basic",
        username: CONFIGS.SOCKET_IO.USERNAME,
        password: bcryptjs.hashSync(CONFIGS.SOCKET_IO.PASSWORD, 10),
    },
});

// Pre Route Middlewares
configurePreRouteMiddleware(app);

// Uncomment to add 5 seconds delay to routes // For Testing Only
// app.use((_req, _res, next) => setTimeout(next, 5000));

// Routes
app.use(routes);

// Error middlewares
configureErrorMiddleware(app);

const PORT: number | string = process.env.PORT || 4000;

// Listen to server port
httpServer.listen(PORT, async () => {
    // verify mailer connection
    await nodemailerInstance.verifyConnection();

    // Initialize Redis connection
    await redisClient.connect();

    // Initialize MongoDB connection
    await connectMongoDB();

    // Setup Socket IO Adapter
    const mongooseCollection = mongoose.connection.collection("socket-adapter-logs");
    await mongooseCollection.createIndex({ createdAt: 1 }, { expireAfterSeconds: 1800, background: true });
    io.adapter(createAdapter(mongooseCollection as any, { addCreatedAtField: true }));

    // Socket IO Auth
    io.use(socketAuth).on("connection", (socket) => {
        new SocketHandler(socket).start();
    });

    console.log(`:::> Server listening on port ${PORT} @ http://localhost:${PORT} in ${String(process.env.NODE_ENV)} mode <:::`);
});

// On server error
app.on("error", (error) => {
    console.error(`<::: An error occurred on the server: \n ${error}`);
});

export default app;
