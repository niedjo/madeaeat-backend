import { Request } from "express";
import { Document } from "mongoose";

export interface IReq extends Request {
  user: {
    userId: string;
  };
}

export interface IGenericUser {
  name: string;
  email: string;
  password: string;
  createJWT(): string;
  comparePassword(candidatePassword: string): Promise<boolean>;
  profileImage?: string;
  phoneNumber?: string;
}
export interface IAdminRestaurant extends IGenericUser {
  ownedRestaurant?: any;
}

export interface IClient extends IGenericUser {
  town?: string;
  age?: string;
}

export interface IAgence extends IGenericUser {
  agence: string;
  profileAgence: string
}

export interface UploadedFiles {
  profileImage?: Express.Multer.File[];
  profileAgence?: Express.Multer.File[];
}

// Définir le type TypeScript pour représenter des éléments non uniformes
export type Item = {
  [key: string]: any; // Les éléments peuvent avoir n'importe quelle structure
};

// Définir le type TypeScript pour le document
export interface CommandeModel extends Document {
  items: Item[]; // Tableau d'éléments de type mixte
}

