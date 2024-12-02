import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import {
  AdminRestaurant,
  Annonce,
  Menu,
  MenuOwner,
  Restaurant,
} from "../db/models/restaurant";
import { StatusCodes } from "http-status-codes";
import { BadRequest, NotFoundError, UnauthenticatedError } from "../errors";
import { IReq } from "../types";
import {
  deleteFileFromCloudinary,
  uploadToCloudinary,
} from "../middlewares/upload";

import jwt, { JwtPayload } from 'jsonwebtoken'

// Authentication controllers

// Creating restaurant administrator
export const signup = async (req: Request, res: Response) => {
  const adminRestaurant = await AdminRestaurant.create({
    ...req.body,
  });
  const token = adminRestaurant.createJWT();
  return res.status(StatusCodes.CREATED).json({
    msg: "Admin user created successfully",
    token,
    admin: adminRestaurant,
  });
};

export const createRestaurant = async (req: Request, res: Response) => {
  const { userId } = (req as any).user;
  if (!userId) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Unauthenticated, authenticate yourself!" });
  }
  const restaurant = await Restaurant.create({
    ...req.body,
    ownedBy: userId,
  });

  // const administrator = await AdminRestaurant.findById(userId);
  const token = jwt.sign(
    {
      userId: restaurant._id,
    },
    process.env.JWT_SECRET!,
    {
      expiresIn: process.env.JWT_LIFETIME!,
    }
  );
  return res.status(StatusCodes.CREATED).json({
    msg: "Restaurant created successfully",
    restaurant,
    token,
  });
};

export const signin = async (req: Request, res: Response) => {
  const { password, email, nameRestaurant } = req.body;
  if (!password || !email || !nameRestaurant) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Please provide all fields" });
  }

  const adminRestaurant = await AdminRestaurant.findOne({ email });
  if (!adminRestaurant) {
    throw new UnauthenticatedError("Invalid email. User not found");
  }
  const isPasswordCorrect = await adminRestaurant?.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new UnauthenticatedError("Invalid password. Please try again");
  }
  // check if restaurant exists
  const restaurant = await Restaurant.findOne({
    name: nameRestaurant,
    ownedBy: adminRestaurant?._id,
  });

  if (!restaurant) {
    throw new NotFoundError("You don't have a restaurant with this name");
  }

  const token = jwt.sign(
    {
      userId: restaurant._id,
    },
    process.env.JWT_SECRET!,
    {
      expiresIn: process.env.JWT_LIFETIME!,
    }
  );
  return res.status(StatusCodes.OK).json({
    msg: "Login into restaurant account successfull",
    token,
  });
};

// le controlleur que daa a ajoutee pour authentifier un administrateur
export const signinAdmin = async (req : Request, res: Response) => {
  const { password, email } = req.body;
  if (!password || !email) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Please provide all fields" });
  }

  const adminRestaurant = await AdminRestaurant.findOne({ email });
  if (!adminRestaurant) {
    throw new UnauthenticatedError("Invalid email. User not found");
  }
  const isPasswordCorrect = await adminRestaurant?.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new UnauthenticatedError("Invalid password. Please try again");
  }

  const token = adminRestaurant.createJWT();
  return res.status(StatusCodes.OK).json({
    msg: "Logged into Admin account successfull",
    token,
  });
}

// Menu controllers
export const createMenuItem = async (req: Request, res: Response) => {
  // Extract the userId from the request object
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new UnauthenticatedError("No token provided or wrong token format");
  }
  const token0 = authHeader.split(" ")[1];

  const decoded = jwt.verify(token0, process.env.JWT_SECRET!) as JwtPayload;

  if (!decoded.userId) {
    throw new BadRequest("Invalid token");
  }

  let userId = decoded.userId;

  const menuInfo = req.body;
  const imageMenu = req.file;
  if (imageMenu) {
    const cloudinaryResponse = await uploadToCloudinary(imageMenu);
    menuInfo.imageMenu = cloudinaryResponse.secure_url;
  }

  const menu = await Menu.create({
    ...menuInfo,
  });

  // je remplace par findById
  const restaurant = await Restaurant.findById(userId);
  await MenuOwner.create({
    menuID: menu._id,
    restaurantID: restaurant?._id,
  });
  return res.status(StatusCodes.CREATED).json({ menu });
};

export const getAllRestaurantMenu = async (req: Request, res: Response) => {
  
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new UnauthenticatedError("No token provided or wrong token format");
  }
  const token0 = authHeader.split(" ")[1];

  const decoded = jwt.verify(token0, process.env.JWT_SECRET!) as JwtPayload;

  if (!decoded.userId) {
    throw new BadRequest("Invalid token");
  }

  let userId = decoded.userId;

  // je remplace par findById
  const restaurant = await Restaurant.findById(userId);
  if (!restaurant) {
    res.status(StatusCodes.NOT_FOUND).json({
      msg: "No restaurnt found",
    });
  }
  const idMenus = await MenuOwner.find({
    restaurantID: restaurant?._id,
  });

  const menus = await Menu.find({
    _id: { $in: idMenus.map((menu) => menu.menuID) },
  });

  return res.status(StatusCodes.OK).json({ menus });
};

export const getMenuByID = async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new UnauthenticatedError("No token provided or wrong token format");
  }
  const token0 = authHeader.split(" ")[1];

  const decoded = jwt.verify(token0, process.env.JWT_SECRET!) as JwtPayload;

  if (!decoded.userId) {
    throw new BadRequest("Invalid token");
  }

  let userId = decoded.userId;

  const { menuID } = req.params;

  const restaurant = await Restaurant.findById(userId);
  
  const menuId = await MenuOwner.findOne({
    restaurantID: restaurant?._id,
    menuID,
  });

  if (!menuId) {
    throw new BadRequest("You don't have a menu with such Id");
  }

  const menu = await Menu.findById(menuID);

  return res.status(StatusCodes.OK).json({
    menu,
  });
};

export const updateMenuItem = async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new UnauthenticatedError("No token provided or wrong token format");
  }
  const token0 = authHeader.split(" ")[1];

  const decoded = jwt.verify(token0, process.env.JWT_SECRET!) as JwtPayload;

  if (!decoded.userId) {
    throw new BadRequest("Invalid token");
  }

  let userId = decoded.userId;

  const { menuID } = req.params;
  // je remplace par findById
  const restaurant = await Restaurant.findById(userId);
  
  const menuId = await MenuOwner.findOne({
    restaurantID: restaurant?._id,
    menuID,
  });

  if (!menuId) {
    throw new BadRequest("You don't have a menu with such Id");
  }
  const menuToUpdate = req.body;
  const imageMenu = req.file;
  if (imageMenu) {
    // Search for menu in database in order to delete it's image from cloudinary
    const menuFromDb = await Menu.findById(menuId);
    menuFromDb?.imageMenu && deleteFileFromCloudinary(menuFromDb.imageMenu);
    // upload new image to cloudinary and get it's url to save in Database
    const cloudinaryResponse = await uploadToCloudinary(imageMenu);
    menuToUpdate.imageMenu = cloudinaryResponse.secure_url;
  }

  const menu = await Menu.findByIdAndUpdate(
    {
      _id: menuID,
    },
    menuToUpdate,
    {
      new: true,
      runValidators: true,
    }
  );

  if (!menu) {
    throw new NotFoundError("No menu found to update");
  }

  return res.status(StatusCodes.OK).json({
    menu,
  });
};

export const deleteMenuItem = async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new UnauthenticatedError("No token provided or wrong token format");
  }
  const token0 = authHeader.split(" ")[1];

  const decoded = jwt.verify(token0, process.env.JWT_SECRET!) as JwtPayload;

  if (!decoded.userId) {
    throw new BadRequest("Invalid token");
  }

  let userId = decoded.userId;

  const { menuID } = req.params;
  const restaurant = await Restaurant.findById(userId);
  
  const menuId = await MenuOwner.findOneAndDelete({
    restaurantID: restaurant?._id,
    menuID,
  });

  if (!menuId) {
    throw new BadRequest("You don't have a menu with such Id");
  }

  const deletedMenu = await Menu.findByIdAndDelete({
    _id: menuID,
  });
  if (!deletedMenu) {
    throw new NotFoundError("No such menu exist");
  }
  if (deletedMenu.imageMenu) {
    await deleteFileFromCloudinary(deletedMenu.imageMenu);
  }

  return res.status(StatusCodes.OK).json({
    msg: "Menu deleted successfully",
  });
};

// Annonce controllers
export const createAnnonce = async (req: Request, res: Response) => {
  // Extract the userId from the request object
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new UnauthenticatedError("No token provided or wrong token format");
  }
  const token0 = authHeader.split(" ")[1];

  const decoded = jwt.verify(token0, process.env.JWT_SECRET!) as JwtPayload;

  if (!decoded.userId) {
    throw new BadRequest("Invalid token");
  }

  let userId = decoded.userId;

  // je remplace par findById
  const restaurant = await Restaurant.findById(userId);
  
  if (!restaurant) {
    throw new BadRequest("Please provide the creator of the annonce");
  }

  const annonce = await Annonce.create({
    ...req.body,
    createdBy: restaurant?._id,
  });

  return res.status(StatusCodes.CREATED).json({
    msg: "Annonce created successfully",
    annonce,
  });
};
export const getAnnonceByID = async (req: Request, res: Response) => {
  const { userId } = (req as any).user;
  const { annonceID } = req.params;
  const restaurantOfAdmin = await Restaurant.findOne({
    ownedBy: userId,
  });
  const annonce = await Annonce.findById({
    _id: annonceID,
    createdBy: restaurantOfAdmin?._id,
  });

  if (!annonce) {
    throw new NotFoundError(`No annonce with id ${annonceID} found`);
  }

  return res.status(StatusCodes.OK).json({
    annonce,
  });
};
export const updateAnnoceByID = async (req: Request, res: Response) => {
  const { userId } = (req as any).user;
  const { annonceID } = req.params;
  const restaurantOfAdmin = await Restaurant.findOne({
    ownedBy: userId,
  });
  const annonce = await Annonce.findByIdAndUpdate(
    {
      _id: annonceID,
      createdBy: restaurantOfAdmin?._id,
    },
    req.body,
    { new: true, runValidators: true }
  );

  if (!annonce) {
    throw new NotFoundError(`No annonce with id ${annonceID} found`);
  }

  return res.status(StatusCodes.OK).json({
    annonce,
  });
};
export const deleteAnnonceByID = async (req: Request, res: Response) => {
  const { userId } = (req as any).user;
  const { annonceID } = req.params;
  const restaurantOfAdmin = await Restaurant.findOne({
    ownedBy: userId,
  });
  const annonce = await Annonce.findByIdAndDelete({
    _id: annonceID,
    createdBy: restaurantOfAdmin?._id,
  });

  if (!annonce) {
    throw new NotFoundError(`No job with id ${annonceID}`);
  }

  return res.status(StatusCodes.OK).json();
};
export const getAllAnnonce = async (req: Request, res: Response) => {
  // Extract the userId from the request object
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new UnauthenticatedError("No token provided or wrong token format");
  }
  const token0 = authHeader.split(" ")[1];

  const decoded = jwt.verify(token0, process.env.JWT_SECRET!) as JwtPayload;

  if (!decoded.userId) {
    throw new BadRequest("Invalid token");
  }

  let userId = decoded.userId;

  // je remplace par findById
  const restaurant = await Restaurant.findById(userId);
  
  const annonce = await Annonce.find({
    createdBy: restaurant?._id,
  }).sort({ createdAt: -1 });

  return res.status(StatusCodes.OK).json({
    annonce,
  });
};

// Profile controllers
export const getRestaurantProfileInfos = async (
  req: Request,
  res: Response
) => {
  const { userId } = (req as any).user;

  const restaurant = await Restaurant.findById(userId)

  if (!restaurant) {
    throw new NotFoundError(`You don't yet have a restaurant`);
  }

  const updateRestaurant = await Restaurant.findByIdAndUpdate(
    {
      _id: restaurant?._id,
    },
    req.body,
    {
      new: true,
      runValidators: true,
    }
  );

  return res.status(StatusCodes.OK).json({
    restaurant,
  });
};

export const updateRestaurantInfos = async (req: Request, res: Response) => {
  // Extract the userId from the request object
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new UnauthenticatedError("No token provided or wrong token format");
  }
  const token0 = authHeader.split(" ")[1];

  const decoded = jwt.verify(token0, process.env.JWT_SECRET!) as JwtPayload;

  if (!decoded.userId) {
    throw new BadRequest("Invalid token");
  }

  let userId = decoded.userId;

  const informationToUpdate = req.body;
  const profile = req.file;
  
  if(informationToUpdate.openingDays) informationToUpdate.openingDays = JSON.parse(informationToUpdate.openingDays); // Décoder le tableau JSON en tableau JavaScript
  
  const restaurantToUpdate = await Restaurant.findById(userId);

  if (!restaurantToUpdate) {
    throw new NotFoundError(`You don't yet have a restaurant`);
  }
  if (profile) {
    // Delete the image from cloudinary in case the user already had an image before uploading the new one
    // restaurantToUpdate.profile &&
    //   deleteFileFromCloudinary(restaurantToUpdate.profile);
    // If the user has a profile image, delete it from Cloudinary
    if (restaurantToUpdate?.profile) {
      await deleteFileFromCloudinary(restaurantToUpdate?.profile);
    }
    // upload new profile image to cloudinary
    const cloudinaryUpload = await uploadToCloudinary(profile);
    informationToUpdate.profile = cloudinaryUpload.secure_url;
  }

  const updatedRestaurant = await Restaurant.findByIdAndUpdate(
    {
      _id: restaurantToUpdate?._id,
    },
    informationToUpdate,
    {
      new: true,
      runValidators: true,
    }
  );

  return res.status(StatusCodes.OK).json({
    restaurant: updatedRestaurant,
  });

};

export const getRestaurantAdminInfos = async (req: Request, res: Response) => {
  // const { userId } = (req as any).user;

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new UnauthenticatedError("No token provided or wrong token format");
  }
  const token0 = authHeader.split(" ")[1];

  const decoded = jwt.verify(token0, process.env.JWT_SECRET!) as JwtPayload;

  if (!decoded.userId) {
    throw new BadRequest("Invalid token");
  }

  let userId = decoded.userId;

  const admin = await AdminRestaurant.findById(userId);

  if (!admin) {
    throw new NotFoundError(`No admin found`);
  }

  return res.status(StatusCodes.OK).json({
    admin,
  });
};

export const updateRestaurantAdminInfos = async (
  req: Request,
  res: Response
) => {
  const { userId } = (req as any).user;

  const { password, ...updateInfos } = req.body;

  const adminProfile = req.file;

  const adminRestaurantToUpdate = await AdminRestaurant.findById(userId);

  if (!adminRestaurantToUpdate) {
    throw new NotFoundError("You don't have an account");
  }

  if (password) {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    updateInfos.password = hashedPassword;
  }

  if (adminProfile) {
    // Delete the already existing user image on cloudinary if exist
    // adminRestaurantToUpdate.profileImage &&
    //   deleteFileFromCloudinary(adminRestaurantToUpdate.profileImage);
    // If the user has a profile image, delete it from Cloudinary
    if (adminRestaurantToUpdate?.profileImage) {
      await deleteFileFromCloudinary(adminRestaurantToUpdate?.profileImage);
    }
    // upload new image to cloudinary and get url to save in database
    const cloudinaryUpload = await uploadToCloudinary(adminProfile);
    // Attach the image url to the object that will be saved in database
    updateInfos.profileImage = cloudinaryUpload.secure_url;
  }

  const updatedAdmin = await AdminRestaurant.findByIdAndUpdate(
    { _id: userId },
    updateInfos,
    {
      new: true,
    }
  );

  if (!updatedAdmin) {
    throw new NotFoundError(`No admin found with id ${userId}`);
  }

  return res.status(StatusCodes.OK).json({
    admin: updatedAdmin,
  });
};
