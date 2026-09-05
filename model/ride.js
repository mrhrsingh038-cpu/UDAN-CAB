
const mongoose = require("mongoose");

const locationSchema = new mongoose.Schema(
    {
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
    },
    {
        _id: false
    }
);

const coordSchema = new mongoose.Schema(
    {
        lat: {
            type: Number,
            default: null
        },
        lng: {
            type: Number,
            default: null
        }
    },
    {
        _id: false
    }
);

const rideSchema = new mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        pickup: {
            type: String,
            required: true,
            trim: true
        },

        destination: {
            type: String,
            required: true,
            trim: true
        },

        cabType: {
            type: String,
            required: true
        },

        fare: {
            type: Number,
            required: true,
            min: 0
        },

        vehicleType: {
            type: String,
            default: null
        },

        parcelType: {
            type: String,
            default: null
        },

        parcelWeight: {
            type: String,
            default: null
        },

        serviceArea: {
            type: String,
            default: "Nalanda"
        },

        status: {
            type: String,
            default: "Searching for driver"
        },

        assignedDriverId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        },

        driverId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        },

        driverName: {
            type: String,
            default: null
        },

        driverEmail: {
            type: String,
            default: null
        },

        driverVehicle: {
            type: String,
            default: null
        },

        driverVehicleType: {
            type: String,
            default: null
        },

        driverRating: {
            type: Number,
            default: null
        },

        assignedDistanceKm: {
            type: Number,
            default: null
        },

        passengerLocation: {
            type: locationSchema,
            default: () => ({})
        },

        destinationLocation: {
            type: coordSchema,
            default: () => ({})
        },

        driverLocation: {
            type: locationSchema,
            default: () => ({})
        }
    },

    {
        timestamps: true
    }
);

module.exports = mongoose.model("Ride", rideSchema);
