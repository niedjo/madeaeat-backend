import express from "express";
import {
  createAnnonce,
  createMenuItem,
  createRestaurant,
  deleteAnnonceByID,
  deleteMenuItem,
  getAllAnnonce,
  getAnnonceByID,
  getMenuByID,
  getAllRestaurantMenu,
  getRestaurantAdminInfos,
  getRestaurantProfileInfos,
  signin,
  signup,
  updateAnnoceByID,
  updateMenuItem,
  updateRestaurantAdminInfos,
  updateRestaurantInfos,
  signinAdmin,
  getAllRestaurantCommande,
} from "../controllers/restaurant";
import { upload } from "../middlewares/upload";
import createRestaurantMiddleware from "../middlewares/createRestaurantMiddleware";

const restaurantRouter = express.Router();

// authentication routes
restaurantRouter.route("/signup").post(signup);
restaurantRouter.route("/signin").post(signin);
  // la route pour chercher un administateur de restaurent avec son email et son passworsd 
restaurantRouter.route("/signin-admin").post(signinAdmin);
restaurantRouter.post("/create-restaurant", createRestaurantMiddleware, createRestaurant);

// menu routes
restaurantRouter
  .route("/menu")
  .post(upload.single("imageMenu"), createMenuItem);
restaurantRouter
  .route("/menu/:menuID")
  .get(getMenuByID)
  .patch(upload.single("imageMenu"), updateMenuItem)
  .delete(deleteMenuItem);
restaurantRouter.route("/menus").get(getAllRestaurantMenu);

// commande routes
restaurantRouter.route("/commandes").get(getAllRestaurantCommande);

// annonce routes
restaurantRouter.route("/annonce").post(createAnnonce);
restaurantRouter
  .route("/annonce/:annonceID")
  .get(getAnnonceByID)
  .patch(updateAnnoceByID)
  .delete(deleteAnnonceByID);
restaurantRouter.route("/annonces").get(getAllAnnonce);

// Profile routes
restaurantRouter
  .route("/profile-restaurant")
  .get(getRestaurantProfileInfos)
  .patch(upload.single("profile-restaurant"), updateRestaurantInfos);
restaurantRouter
  .route("/profile-admin")
  .get(getRestaurantAdminInfos)
  .patch(upload.single("profile-admin"), updateRestaurantAdminInfos);

export default restaurantRouter;
