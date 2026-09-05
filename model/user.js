const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            default: "UDAN User",
            trim: true
        },

        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true
        },

        password: {
            type: String,
            required: true
        },

        role: {
            type: String,
            enum: ["passenger", "driver", "admin"],
            required: true
        },

        city: {
            type: String,
            default: "Nalanda",
            trim: true
        },

        vehicleType: {
            type: String,
            default: "",
            trim: true
        },

        vehicleNumber: {
            type: String,
            default: "",
            trim: true
        },

        license: {
            type: String,
            default: "",
            trim: true
        },

        rating: {
            type: Number,
            default: 4.8
        },

        online: {
            type: Boolean,
            default: false
        },

        blocked: {
            type: Boolean,
            default: false
        },

        blockedReason: {
            type: String,
            default: ""
        },

        blockedAt: {
            type: Date,
            default: null
        },

        location: {
            lat: {
                type: Number,
                default: null
            },

            lng: {
                type: Number,
                default: null
            },

            accuracy: {
                type: Number,
                default: null
            },

            updatedAt: {
                type: Date,
                default: null
            }
        }
    },

    {
        timestamps: true
    }
);

module.exports = mongoose.model("User", userSchema);
