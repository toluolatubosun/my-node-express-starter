import type { Socket } from "socket.io";

class SocketHandler {
    private socket: Socket;

    constructor(socket: Socket) {
        this.socket = socket;
    }

    async start() {
        // Setup Event Listeners
        // =================================================================================
        this.socket.on("join-room", async (payload: { room_id: string }) => {
            try {
                this.socket.join(payload.room_id);
            } catch (error: any) {
                this.socket.emit("error", { message: error.message || "An error occurred" });
            }
        });
    }
}

export default SocketHandler;
