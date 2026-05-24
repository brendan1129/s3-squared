import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const s3Client = new S3Client({ region: process.env.AWS_REGION || "us-east-2" });
const BUCKET_NAME = process.env.BUCKET_NAME;

export const getUploadUrl = async (event) => {
    try {
        // 1. Placeholder for your future user authentication mechanism
        const testUserId = "user_982347239"; 
        
        // 2. Parse payload from client application
        if (!event.body) {
            return {
                statusCode: 400,
                body: JSON.stringify({ error: "Missing request body" })
            };
        }
        
        const { fileName, mimeType } = JSON.parse(event.body);
        
        if (!fileName || !mimeType) {
            return {
                statusCode: 400,
                body: JSON.stringify({ error: "fileName and mimeType are required fields." })
            };
        }
        
        // 3. Define the multi-tenant key destination paths
        const s3Key = `users/${testUserId}/${fileName}`;
        
        // 4. Set up the target S3 command configurations
        const command = new PutObjectCommand({
            Bucket: BUCKET_NAME,
            Key: s3Key,
            ContentType: mimeType
        });
        
        // 5. Generate a secure pre-signed link valid for 5 minutes (300 seconds)
        const uploadUrl = await getSignedUrl(s3Client, command, { expiresIn: 300 });
        
        // 6. Return response payload back to client
        return {
            statusCode: 200,
            headers: { 
                "Content-Type": "application/json",
                // Enable CORS so your desktop app or browser can hit this endpoint safely
                "Access-Control-Allow-Origin": "*" 
            },
            body: JSON.stringify({ 
                uploadUrl, 
                storageKey: s3Key 
            })
        };
        
    } catch (error) {
        console.error("Error generating pre-signed URL:", error);
        return {
            statusCode: 500,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ error: "Internal server error details: " + error.message })
        };
    }
};