{asyncHandler}  It is a wrapper function
 => It automatically catches errors from async functions and passes them to Express error middleware.

 
Access Token	   |     Refresh Token
------------------------------------------
Short expiry	        Long expiry
Used to access APIs     Usedgeneratenew access token
Not stored in DB	    Stored in DB
Sent in every request   Used occasionally