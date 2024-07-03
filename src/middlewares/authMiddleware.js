import { error } from "console";
import { StatusCodes } from "http-status-codes";
import {
  ACCESS_TOKEN_SECRET_SIGNATURE,
  JwtProvider,
} from "~/providers/JwtProvider";

// Middleware này sẽ đảm nhiệm việc quan trọng: lấy và xác thực JWT accessToken nhận đc từ FE có hợp lệ hay kh
const isAuthorized = async (req, res, next) => {
  //cách 1: lấy accesstoken nằm trong req cookies phía client - withCredentials trong file authorizeAxios và credentials trong CORS
  // const accessTokenFromCookie = req.cookies?.accessToken;
  // // console.log("accessTokenFromCookie: ", accessTokenFromCookie);
  // if (!accessTokenFromCookie) {
  //   res
  //     .status(StatusCodes.UNAUTHORIZED)
  //     .json({ message: "Unauthorized! (token not found)" });
  //   return;
  // }

  //cách 2: lấy accesstoken trong trường hợp FE lưu localStorage và gửi lên thông qua header authorization
  const accessTokenFromHeader = req.headers.authorization;
  // console.log("accessTokenFromHeader: ", accessTokenFromHeader);
  if (!accessTokenFromHeader) {
    res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: "Unauthorized! (token not found)" });
    return;
  }

  try {
    //bước 1: thực hiện giải mã token xem có hợp lệ không
    const accessTokenDecoded = await JwtProvider.verifyToken(
      // accessTokenFromCookie, // dùng theo cách 1
      accessTokenFromHeader.substring("Bearer ".length), // dùng theo cách 2
      ACCESS_TOKEN_SECRET_SIGNATURE
    );

    //bước 2: Quan trọng: nếu token hợp lệ, thì sẽ phải lưu thông tin giải mã được vào req.jwtDecoded, để sử dụng cho các tầng cần sử lí ở phía sau
    req.jwtDecoded = accessTokenDecoded;

    //bước 3: cho phép request đi tiếp
    next();
  } catch (error) {
    console.log("🚀 ~ isAuthorized ~ err:", error);

    //th1: accessToken hết hạn thì trả về mã lỗi GONE - 410 cho FE để gọi api refreshToken
    if (error.message?.includes("jwt expired")) {
      res.status(StatusCodes.GONE).json({ message: "need to refresh token" });
      return;
    }
    // UNAUTHORIZED
    // GONE
    //th2: accessToken hết hạn không do hết hạn thì trả về mã lỗi 401 cho FE xử lí logout
    res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: "Unauthorized! Please login" });
  }
};

export const authMiddleware = {
  isAuthorized,
};
