import mongoose from "mongoose";
import { Schema } from "mongoose";


const commandeSchema = new Schema({
  // menuID: {
  //   type: Schema.Types.ObjectId,
  //   ref: "Menu",
  //   required: [true, "Please precise the menu ordered"],
  // },
  // status: {
  //   type: String,
  //   enum: ["pending", "accepted", "rejected"],
  //   default: "pending",
  // },
  // quantity: {
  //   type: Number,
  //   default: 1,
  // },
  // date: {
  //   type: Date,
  //   default: Date.now,
  // },
  clientID: {
    type: Schema.Types.ObjectId,
    ref: "Client",
    required: [true, "Please precise the client who ordered"],
  },
  frais_de_livraison : {
    type : String,
  },
  items: [{ type: Schema.Types.Mixed }],
  address: {
    type: String,
    requied: [true, "Please precise the address of delivery"],
  },
  paymentPhoneNumber: {
    type: String,
    requied: [true, "Please precise the phone number for payment"],
  },
  valede_par_restaurateur : {
    type : Boolean,
  },
  valede_par_madeaeat : {
    type : Boolean,
  },
  livree : {
    type : Boolean,
  }
},
{
  timestamps: true,
});

const CommandeModel = mongoose.model("Commande", commandeSchema);

export default CommandeModel;
