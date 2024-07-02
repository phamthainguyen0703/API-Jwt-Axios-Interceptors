import { StatusCodes } from "http-status-codes";
import ms from "ms";
import {
  ACCESS_TOKEN_SECRET_SIGNATURE,
  JwtProvider,
  REFRESH_TOKEN_SECRET_SIGNATURE,
} from "~/providers/JwtProvider";

const MOCK_DATABASE = {
  USER: {
    ID: "trungquandev-sample-id-12345678",
    EMAIL: "trungquandev.official@gmail.com",
    PASSWORD: "trungquandev@123",
  },
};

const login = async (req, res) => {
  try {
    if (
      req.body.email !== MOCK_DATABASE.USER.EMAIL ||
      req.body.password !== MOCK_DATABASE.USER.PASSWORD
    ) {
      res
        .status(StatusCodes.FORBIDDEN)
        .json({ message: "Your email or password is incorrect!" });
      return;
    }

    // Trường hợp nhập đúng thông tin tài khoản, tạo token và trả về cho phía Client
    const userInfo = {
      id: MOCK_DATABASE.USER.ID,
      email: MOCK_DATABASE.USER.EMAIL,
    };

    // //tạo ra 2 loại token, accessToken và refreshToken để trả về cho phía FE
    const accessToken = await JwtProvider.generateToken(
      userInfo,
      ACCESS_TOKEN_SECRET_SIGNATURE,
      "1h"
    );

    const refreshToken = await JwtProvider.generateToken(
      userInfo,
      REFRESH_TOKEN_SECRET_SIGNATURE,
      "14 days"
    );

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: ms("14 days"),
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: ms("14 days"),
    });

    // trả về thông tin user cũng như trả về Tokens cho trường hợp phía FE cần lưu Tokens vào Localstorage

    res.status(StatusCodes.OK).json({
      ...userInfo,
      accessToken,
      refreshToken,
      // message: "Logout API success!",
    });
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error);
  }
};

const logout = async (req, res) => {
  try {
    // xóa cookie
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    res.status(StatusCodes.OK).json({ message: "Logout API success!" });
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error);
  }
};

const refreshToken = async (req, res) => {
  try {
    // Do something
    res.status(StatusCodes.OK).json({ message: " Refresh Token API success." });
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error);
  }
};

export const userController = {
  login,
  logout,
  refreshToken,
};
