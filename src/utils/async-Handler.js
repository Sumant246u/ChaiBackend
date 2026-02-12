 const asyncHandler = (requestHandler)=>{
   return (req,res,next)=>{
        Promise.resolve(requestHandler(req,res,next)).
        catch((err)=>next(err));
    };
 };

export {asyncHandler} //It automatically catches errors from async functions and passes them to Express error middleware.


// const asyncHandler = (fn)=>async (req,res,next)=>{
//     try {
//        await fn(req,res,next) 
//     } catch (error) {
//         res.status(error.code || 500).json({
//             success:false,
//             message:error.message
//         })
//     }
// }


