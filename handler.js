
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { ListObjectsV2Command } from "@aws-sdk/client-s3";

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

function isValidFileExtension(fileName, clientMimeType) {
    const ext = fileName.split('.').last?.toLowerCase() || '';
    const expectedMime = ALLOWED_MIME_TYPES[ext];
    // Extension must be in our whitelist, and matching the explicit request header content-type
    return expectedMime && expectedMime === clientMimeType;
}
// FORCE the exact regional endpoint target routing
const s3Client = new S3Client({ 
    region: "us-east-2",
    endpoint: "https://s3.us-east-2.amazonaws.com"
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
                body: json.stringify({ error: "Unauthorized access profile identifier context missing." })
            };
        }
        
        if (!event.body) return { statusCode: 400, body: JSON.stringify({ error: "Missing body" }) };
        const { fileName, mimeType } = JSON.parse(event.body);
        
        // 2. RUN STRICT FILE ATTRIBUTE SECURITY CHECKS
        const ext = fileName.split('.').pop()?.toLowerCase() || '';
        const expectedMime = ALLOWED_MIME_TYPES[ext];
        
        if (!expectedMime || expectedMime !== mimeType) {
            return {
                statusCode: 403,
                body: JSON.stringify({ error: `File type restriction violation. Extension .${ext} conflicts with MIME verification mapping.` })
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

        // Get the current virtual directory path sent from Flutter (default to root)
        const queryParams = event.queryStringParameters || {};
        const virtualPath = queryParams.prefix || ""; // e.g., "Photos/" or ""
        
        // S3 uses delimiter '/' to mimic traditional file systems logically
        const userPrefix = `users/${userId}/${virtualPath}`;

        const command = new ListObjectsV2Command({
            Bucket: BUCKET_NAME,
            Prefix: userPrefix,
            Delimiter: "/" 
        });

        const s3Response = await s3Client.send(command);

        // 1. Extract Subfolders (S3 calls these CommonPrefixes)
        const folders = (s3Response.CommonPrefixes || []).map(cp => {
            // Strip out the master path prefix so Flutter just gets the folder name
            const fullPath = cp.Prefix;
            return fullPath.replace(`users/${userId}/`, "");
        });

        // 2. Extract Files
        const files = (s3Response.Contents || [])
            .filter(item => item.Key !== userPrefix) // Exclude the directory root itself
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