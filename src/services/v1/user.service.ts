import { z } from "zod";
import bcryptjs from "bcryptjs";
import { Request } from "express";

import { CONFIGS } from "@/configs";
import CustomError from "@/utilities/custom-error";
import UserModel, { IUser } from "@/models/user.model";
import { extractZodError } from "@/utilities/helpful-methods";

class UserService {
    async getUserSession({ $currentUser }: Partial<Request>) {
        const { error, data } = z
            .object({
                $currentUser: z.custom<IUser>(),
            })
            .safeParse({ $currentUser });
        if (error) throw new CustomError(extractZodError(error));

        return await UserModel.findOne({ _id: data.$currentUser._id });
    }

    async updateProfile({ body, $currentUser }: Partial<Request>) {
        const { error, data } = z
            .object({
                body: z.object({
                    first_name: z.string().trim(),
                    last_name: z.string().trim(),
                }),
                $currentUser: z.custom<IUser>(),
            })
            .safeParse({ body, $currentUser });
        if (error) throw new CustomError(extractZodError(error));

        // Check if user exists
        const user = await UserModel.findOneAndUpdate({ _id: data.$currentUser._id }, { $set: data.body }, { new: true });
        if (!user) throw new CustomError("invalid user id", 404);

        return data.body;
    }

    async updatePassword({ body, $currentUser }: Partial<Request>) {
        const { error, data } = z
            .object({
                body: z.object({
                    new_password: z.string().trim(),
                    current_password: z.string().trim(),
                }),
                $currentUser: z.custom<IUser>(),
            })
            .safeParse({ body, $currentUser });
        if (error) throw new CustomError(extractZodError(error));

        // Check if user exists
        const user = await UserModel.findOne({ _id: data.$currentUser._id }).select("+password");
        if (!user) throw new CustomError("invalid user id", 404);

        // Check if password is correct
        const isPasswordCorrect = await bcryptjs.compare(data.body.current_password, user.password || "");
        if (!isPasswordCorrect) throw new CustomError("incorrect password", 400);

        // Hash new password and update user
        const passwordHash = await bcryptjs.hash(data.body.new_password, CONFIGS.BCRYPT_SALT);
        await UserModel.updateOne({ _id: user._id }, { $set: { password: passwordHash } });

        return;
    }
}

export default new UserService();
