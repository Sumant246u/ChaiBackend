import { v2 as cloudinary } from 'cloudinary'
import fs from "fs"


cloudinary.config({ 
  cloud_name:process.env.CLOUDINARY_CLOUD_NAME , 
  api_key:process.env.CLOUDINARY_API_KEY , 
  api_secret:process.env.CLOUDINARY_SECRET_KEY
});


const uploadOnCloudinary = async (localFilepath)=>{
    try {
        if(!localFilepath) return null
        // upload the file on cloudinary
     const response =  await cloudinary.uploader.upload(localFilepath,{
            resource_type:"auto"
        })
        // file has been uploaded successfully
        console.log("file uploaded", response.url);
        // fs.unlinkSync(localFilepath)  //for remove localImage
        return response;

    } catch (error) {
        fs.unlinkSync(localFilepath)  //remove the locallysaved tem file as the upload operation got failed
        return null
    }
}

export {uploadOnCloudinary}