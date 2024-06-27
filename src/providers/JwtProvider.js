import JWT from "jsonwebtoken";

// func tạo mới token( 3 tham số đầu vào )
// userInfo: những thông tin muốn đính kèm vào token
// secretSignature: chuỗi bí mật
// tokenLife: thời gian sống của token
const generateToken = async (userInfo, secretSignature, tokenLife) => {
  try {
    //
    return JWT.sign(userInfo, secretSignature, {
      algorithm: "HS256",
      expiresIn: tokenLife,
    });
  } catch (error) {
    throw new Error(error);
  }
};

// func kiểm tra 1 token có hợp lệ hay không
const verifyToken = async (token, secretSignature) => {
  try {
    //
    return JWT.verify(token, secretSignature);
  } catch (error) {
    throw new Error(error);
  }
};

export const JwtProvider = {
  generateToken,
  verifyToken,
};
