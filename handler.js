import {
    S3Client,
    PutObjectCommand,
    ListObjectsV2Command,
    DeleteObjectCommand,
    GetObjectCommand,
    CopyObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const ALLOWED_MIME_TYPES = {
    'jpg':  'image/jpeg',
    'jpeg': 'image/jpeg',
    'png':  'image/png',
    'gif':  'image/gif',
    'mp4':  'video/mp4',
    'mov':  'video/quicktime',
    'pdf':  'application/pdf'
};

const s3Client = new S3Client({ region: "us-east-1" });
const BUCKET_NAME = process.env.BUCKET_NAME;

function getUserId(event) {
    return event.requestContext?.authorizer?.jwt?.claims?.sub || null;
}

function isValidRelativeKey(key) {
    return (
        typeof key === 'string' &&
        key.length > 0 &&
        key.length < 1024 &&
        !key.includes('..') &&
        !key.startsWith('/') &&
        !/[\x00-\x1f]/.test(key)
    );
}

function unauthorized() {
    return { statusCode: 401, body: JSON.stringify({ error: "Unauthorized: missing identity context." }) };
}

function badRequest(msg) {
    return { statusCode: 400, body: JSON.stringify({ error: msg }) };
}

const jsonHeaders = { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" };

// ── Upload presigned URL ──────────────────────────────────────────────────────
export const getUploadUrl = async (event) => {
    try {
        const userId = getUserId(event);
        if (!userId) return unauthorized();
        if (!event.body) return badRequest("Missing body");

        const { fileName, mimeType } = JSON.parse(event.body);
        if (!fileName || !mimeType) return badRequest("fileName and mimeType are required");
        if (!isValidRelativeKey(fileName)) return badRequest("Invalid file name");

        const ext = fileName.split('.').pop()?.toLowerCase() || '';
        const expectedMime = ALLOWED_MIME_TYPES[ext];
        if (!expectedMime || expectedMime !== mimeType) {
            return { statusCode: 403, body: JSON.stringify({ error: `File type not permitted: .${ext} with ${mimeType}` }) };
        }

        const s3Key = `users/${userId}/${fileName}`;
        const uploadUrl = await getSignedUrl(s3Client, new PutObjectCommand({
            Bucket: BUCKET_NAME, Key: s3Key, ContentType: mimeType
        }), { expiresIn: 300 });

        return { statusCode: 200, headers: jsonHeaders, body: JSON.stringify({ uploadUrl, storageKey: s3Key }) };
    } catch (error) {
        return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
    }
};

// ── List files ────────────────────────────────────────────────────────────────
export const listFiles = async (event) => {
    try {
        const userId = getUserId(event);
        if (!userId) return unauthorized();

        const virtualPath = event.queryStringParameters?.prefix || "";
        const userPrefix = `users/${userId}/${virtualPath}`;

        const s3Response = await s3Client.send(new ListObjectsV2Command({
            Bucket: BUCKET_NAME, Prefix: userPrefix, Delimiter: "/"
        }));

        const folders = (s3Response.CommonPrefixes || []).map(cp =>
            cp.Prefix.replace(`users/${userId}/`, "")
        );
        const files = (s3Response.Contents || [])
            .filter(item => item.Key !== userPrefix)
            .map(item => ({
                name: item.Key.replace(`users/${userId}/${virtualPath}`, ""),
                size: item.Size,
                lastModified: item.LastModified
            }));

        return { statusCode: 200, headers: jsonHeaders, body: JSON.stringify({ folders, files }) };
    } catch (error) {
        return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
    }
};

// ── Download presigned URL ────────────────────────────────────────────────────
export const getDownloadUrl = async (event) => {
    try {
        const userId = getUserId(event);
        if (!userId) return unauthorized();

        const fileKey = event.queryStringParameters?.key || '';
        if (!isValidRelativeKey(fileKey)) return badRequest("Invalid file key");

        const s3Key = `users/${userId}/${fileKey}`;
        const downloadUrl = await getSignedUrl(s3Client, new GetObjectCommand({
            Bucket: BUCKET_NAME, Key: s3Key
        }), { expiresIn: 300 });

        return { statusCode: 200, headers: jsonHeaders, body: JSON.stringify({ downloadUrl }) };
    } catch (error) {
        return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
    }
};

// ── Delete file ───────────────────────────────────────────────────────────────
export const deleteFile = async (event) => {
    try {
        const userId = getUserId(event);
        if (!userId) return unauthorized();
        if (!event.body) return badRequest("Missing body");

        const { fileKey } = JSON.parse(event.body);
        if (!isValidRelativeKey(fileKey)) return badRequest("Invalid file key");

        await s3Client.send(new DeleteObjectCommand({
            Bucket: BUCKET_NAME, Key: `users/${userId}/${fileKey}`
        }));

        return { statusCode: 200, headers: jsonHeaders, body: JSON.stringify({ success: true }) };
    } catch (error) {
        return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
    }
};

// ── Rename file (same directory, filename only) ───────────────────────────────
export const renameFile = async (event) => {
    try {
        const userId = getUserId(event);
        if (!userId) return unauthorized();
        if (!event.body) return badRequest("Missing body");

        const { fileKey, newName } = JSON.parse(event.body);
        if (!isValidRelativeKey(fileKey)) return badRequest("Invalid file key");
        if (!newName || newName.includes('/') || newName.includes('..') || newName.length > 255) {
            return badRequest("Invalid new name — must be a bare filename with no slashes");
        }

        const lastSlash = fileKey.lastIndexOf('/');
        const dir = lastSlash >= 0 ? fileKey.substring(0, lastSlash + 1) : '';
        const oldS3Key = `users/${userId}/${fileKey}`;
        const newS3Key = `users/${userId}/${dir}${newName}`;

        if (oldS3Key === newS3Key) {
            return { statusCode: 200, body: JSON.stringify({ success: true, unchanged: true }) };
        }

        await s3Client.send(new CopyObjectCommand({
            Bucket: BUCKET_NAME, CopySource: `${BUCKET_NAME}/${oldS3Key}`, Key: newS3Key
        }));
        await s3Client.send(new DeleteObjectCommand({ Bucket: BUCKET_NAME, Key: oldS3Key }));

        return { statusCode: 200, headers: jsonHeaders, body: JSON.stringify({ success: true }) };
    } catch (error) {
        return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
    }
};

// ── Move file (cross-directory, preserves filename) ───────────────────────────
export const moveFile = async (event) => {
    try {
        const userId = getUserId(event);
        if (!userId) return unauthorized();
        if (!event.body) return badRequest("Missing body");

        const { sourceKey, destinationFolder } = JSON.parse(event.body);
        if (!isValidRelativeKey(sourceKey)) return badRequest("Invalid source key");

        // destinationFolder is "" for root, or "Folder/Sub/" with trailing slash
        if (destinationFolder !== '' && (!destinationFolder.endsWith('/') || !isValidRelativeKey(destinationFolder))) {
            return badRequest("Invalid destination folder — must be empty (root) or end with '/'");
        }

        const fileName = sourceKey.split('/').pop();
        const oldS3Key = `users/${userId}/${sourceKey}`;
        const newS3Key = `users/${userId}/${destinationFolder}${fileName}`;

        if (oldS3Key === newS3Key) {
            return { statusCode: 200, body: JSON.stringify({ success: true, unchanged: true }) };
        }

        await s3Client.send(new CopyObjectCommand({
            Bucket: BUCKET_NAME, CopySource: `${BUCKET_NAME}/${oldS3Key}`, Key: newS3Key
        }));
        await s3Client.send(new DeleteObjectCommand({ Bucket: BUCKET_NAME, Key: oldS3Key }));

        return { statusCode: 200, headers: jsonHeaders, body: JSON.stringify({ success: true }) };
    } catch (error) {
        return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
    }
};

// ── Create folder ─────────────────────────────────────────────────────────────
export const createFolder = async (event) => {
    try {
        const userId = getUserId(event);
        if (!userId) return unauthorized();
        if (!event.body) return badRequest("Missing body");

        const { folderPath } = JSON.parse(event.body);
        if (!folderPath || !folderPath.endsWith('/') || !isValidRelativeKey(folderPath) || /[<>:"|?*]/.test(folderPath)) {
            return badRequest("Invalid folder path — must end with '/' and contain no special characters");
        }

        await s3Client.send(new PutObjectCommand({
            Bucket: BUCKET_NAME,
            Key: `users/${userId}/${folderPath}`,
            Body: '',
            ContentType: 'application/x-directory'
        }));

        return { statusCode: 200, headers: jsonHeaders, body: JSON.stringify({ success: true }) };
    } catch (error) {
        return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
    }
};