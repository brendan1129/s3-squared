import { S3Client, PutObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

// Strict map correlating expected file extensions to matching explicit content-types
const ALLOWED_MIME_TYPES = {
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'mp4': 'video/mp4',
    'mov': 'video/quicktime',
    'pdf': 'application/pdf'
};

// Region matches the serverless.yml provider region (us-east-1)
const s3Client = new S3Client({
    region: "us-east-1"
});

const BUCKET_NAME = process.env.BUCKET_NAME;

export const getUploadUrl = async (event) => {
    try {
        // 1. EXTRACT SECURE AUTHENTICATED COGNITO USER ID
        // API Gateway populates these claims automatically when authorization passes
        const userId = event.requestContext?.authorizer?.jwt?.claims?.sub;

        if (!userId) {
            return {
                statusCode: 401,
                // FIX: was `json.stringify` (undefined) — crashed instead of returning 401
                body: JSON.stringify({ error: "Unauthorized: missing identity context." })
            };
        }

        if (!event.body) {
            return { statusCode: 400, body: JSON.stringify({ error: "Missing body" }) };
        }

        const { fileName, mimeType } = JSON.parse(event.body);

        if (!fileName || !mimeType) {
            return { statusCode: 400, body: JSON.stringify({ error: "fileName and mimeType are required" }) };
        }

        // 2. RUN STRICT FILE ATTRIBUTE SECURITY CHECKS
        // FIX: was `.last` which is undefined on JS arrays — use `.pop()` on a copy
        const ext = fileName.split('.').pop()?.toLowerCase() || '';
        const expectedMime = ALLOWED_MIME_TYPES[ext];

        if (!expectedMime || expectedMime !== mimeType) {
            return {
                statusCode: 403,
                body: JSON.stringify({ error: `File type not permitted: .${ext} with MIME type ${mimeType}` })
            };
        }

        // 3. ISOLATE ACCESS TO SPECIFIC USER SUBDIRECTORY PREFIXES
        const s3Key = `users/${userId}/${fileName}`;

        const command = new PutObjectCommand({
            Bucket: BUCKET_NAME,
            Key: s3Key,
            ContentType: mimeType
        });

        const uploadUrl = await getSignedUrl(s3Client, command, { expiresIn: 300 });

        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            body: JSON.stringify({ uploadUrl, storageKey: s3Key })
        };

    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: error.message })
        };
    }
};

export const listFiles = async (event) => {
    try {
        const userId = event.requestContext?.authorizer?.jwt?.claims?.sub;
        if (!userId) {
            return { statusCode: 401, body: JSON.stringify({ error: "Unauthorized" }) };
        }

        const queryParams = event.queryStringParameters || {};
        const virtualPath = queryParams.prefix || "";

        const userPrefix = `users/${userId}/${virtualPath}`;

        const command = new ListObjectsV2Command({
            Bucket: BUCKET_NAME,
            Prefix: userPrefix,
            Delimiter: "/"
        });

        const s3Response = await s3Client.send(command);

        // Extract subfolders (S3 CommonPrefixes)
        const folders = (s3Response.CommonPrefixes || []).map(cp => {
            return cp.Prefix.replace(`users/${userId}/`, "");
        });

        // Extract files, excluding the directory placeholder key itself
        const files = (s3Response.Contents || [])
            .filter(item => item.Key !== userPrefix)
            .map(item => ({
                name: item.Key.replace(`users/${userId}/${virtualPath}`, ""),
                size: item.Size,
                lastModified: item.LastModified
            }));

        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            body: JSON.stringify({ folders, files })
        };

    } catch (error) {
        console.error("List files error:", error);
        return {
            statusCode: 500,
            body: JSON.stringify({ error: error.message })
        };
    }
};
