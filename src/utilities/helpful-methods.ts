import { ZodError } from "zod";

export const extractZodError = (error: ZodError<any>) => {
    // console.log("error", error);

    const formattedError = new Set<{ message: string }>();

    for (const singleError of error.errors) {
        switch (singleError.code) {
            case "invalid_type": {
                if (singleError.message.includes("Expected")) {
                    // to catch invalid type
                    formattedError.add({ message: `${singleError.path.join(".")} ${singleError.message.toLowerCase()}` });
                } else if (singleError.message === "Required") {
                    // to catch objects that are required
                    formattedError.add({ message: `${singleError.path.join(".")} is required` });
                } else {
                    formattedError.add({ message: `${singleError.message}` });
                }
                break;
            }

            case "invalid_enum_value": {
                if (singleError.message.includes("Expected")) {
                    // messsage -- Expected 'option1', 'option2', 'option3' but got 'option4'
                    formattedError.add({ message: `${singleError.path.join(".")} is invalid. ${singleError.message.substring(20)}` });
                } else {
                    formattedError.add({ message: `${singleError.message}` });
                }

                break;
            }

            default: {
                formattedError.add({ message: `${singleError.message}` });
                break;
            }
        }
    }

    // return first error message
    return formattedError.values().next().value?.message || "a validation error occurred";
};

export const trimObjectStrings = (obj: any) => {
    if (typeof obj === "string") {
        return obj.trim();
    } else if (typeof obj === "object") {
        for (const key in obj) {
            // eslint-disable-next-line no-prototype-builtins
            if (obj.hasOwnProperty(key)) {
                obj[key] = trimObjectStrings(obj[key]);
            }
        }

        return obj;
    } else {
        return obj;
    }
};
