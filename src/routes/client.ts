import express from "express";
import {
  getAllAnnouncements,
  getAllMenus,
  getAllRestaurantProfiles,
  getAllUserCommands,
  getRestaurantById,
  getSingleRestaurantMenu,
  getUserProfile,
  makeCommand,
  markAnnouncementAsRead,
  signin,
  signup,
  updateUserProfile,
} from "../controllers/client";
import { upload } from "../middlewares/upload";

const clientRouter = express.Router();

// Authentication routes
clientRouter.route("/signup").post(signup);
clientRouter.route("/signin").post(signin);

// Restaurant routes
clientRouter.get("/restaurant", getAllRestaurantProfiles);
clientRouter.get("/restaurant/:restaurantID", getRestaurantById);
clientRouter.get("/restaurant/:restaurantID/:menuID", getSingleRestaurantMenu);
clientRouter.get("/announcements", getAllAnnouncements);
clientRouter.post("/announcements/markasread/:id", markAnnouncementAsRead);

// Menu routes
clientRouter.get("/menus", getAllMenus);

// Commande routes
clientRouter.get("/commandes", getAllUserCommands);
clientRouter.post("/commande", makeCommand);

// profile routes
clientRouter.get("/profile", getUserProfile);
clientRouter.patch(
  "/profile",
  upload.single("profile-user"),
  updateUserProfile
);

export default clientRouter;
