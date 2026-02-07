const fs = require('fs').promises;
const path = require('path');

async function generateThumbnail(filePath, outputDir, size = 150) {
    try {
        const filename = path.basename(filePath, path.extname(filePath));
        const thumbnailPath = path.join(outputDir, `${filename}_thumb.jpg`);
        
        // Check if sharp is available
        let sharp;
        try {
            sharp = require('sharp');
        } catch (sharpError) {
            console.warn('Sharp not available, using simulated thumbnail generation');
            // Create a simulated thumbnail file
            const simulatedThumbnail = `
                <svg width="${size}" height="${size}" xmlns="http://www.w3.org/2000/svg">
                    <rect width="${size}" height="${size}" fill="#f0f0f0"/>
                    <text x="${size/2}" y="${size/2}" font-family="Arial" font-size="12" text-anchor="middle" fill="#666">Thumbnail</text>
                    <text x="${size/2}" y="${size/2 + 15}" font-family="Arial" font-size="10" text-anchor="middle" fill="#999">${size}x${size}</text>
                </svg>
            `;
            await fs.writeFile(thumbnailPath.replace('.jpg', '.svg'), simulatedThumbnail);
            
            return {
                path: thumbnailPath.replace('.jpg', '.svg'),
                url: `/uploads/thumbnails/${path.basename(thumbnailPath.replace('.jpg', '.svg'))}`,
                dimensions: `${size}x${size}`,
                simulated: true,
                format: 'svg'
            };
        }
        
        // Use sharp if available
        await sharp(filePath)
            .resize(size, size, { fit: 'inside' })
            .jpeg({ quality: 80 })
            .toFile(thumbnailPath);
        
        return {
            path: thumbnailPath,
            url: `/uploads/thumbnails/${path.basename(thumbnailPath)}`,
            dimensions: `${size}x${size}`,
            simulated: false,
            format: 'jpeg'
        };
    } catch (error) {
        console.error('Thumbnail generation failed:', error);
        
        // Fallback: Create a simple placeholder
        const fallbackPath = path.join(outputDir, 'fallback_thumbnail.svg');
        const fallbackSvg = `
            <svg width="150" height="150" xmlns="http://www.w3.org/2000/svg">
                <rect width="150" height="150" fill="#e0e0e0"/>
                <text x="75" y="75" font-family="Arial" font-size="12" text-anchor="middle" fill="#666" alignment-baseline="middle">Thumbnail</text>
            </svg>
        `;
        
        try {
            await fs.writeFile(fallbackPath, fallbackSvg);
            return {
                path: fallbackPath,
                url: '/uploads/thumbnails/fallback_thumbnail.svg',
                dimensions: '150x150',
                simulated: true,
                format: 'svg',
                error: error.message
            };
        } catch (writeError) {
            console.error('Failed to create fallback thumbnail:', writeError);
            return null;
        }
    }
}

module.exports = { generateThumbnail };