import { z } from "zod";
import { Request } from "express";

import ConfigModel from "@/models/config.model";
import CustomError from "@/utilities/custom-error";
import { extractZodError } from "@/utilities/helpful-methods";

class ConfigService {
    async getConfig({ params }: Partial<Request>) {
        const { error, data } = z
            .object({
                params: z.object({
                    key: z.string().trim(),
                }),
            })
            .safeParse({ params });
        if (error) throw new CustomError(extractZodError(error));

        const config = await ConfigModel.findOne({ key: data.params.key });
        if (!config) throw new CustomError(`${data.params.key} not found`, 404);

        return config.value;
    }
}

export default new ConfigService();
