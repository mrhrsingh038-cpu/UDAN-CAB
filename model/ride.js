const mongoose = require("mongoose");


/* =========================================================
   LOCATION SCHEMA
========================================================= */

const locationSchema =
  new mongoose.Schema(
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


/* =========================================================
   COORDINATE SCHEMA
========================================================= */

const coordSchema =
  new mongoose.Schema(
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


/* =========================================================
   RIDE SCHEMA
========================================================= */

const rideSchema =
  new mongoose.Schema(
    {

      /* =====================================================
         PASSENGER
      ===================================================== */

      userId: {
        type:
          mongoose.Schema.Types.ObjectId,

        ref: "User",

        required: true
      },


      /* =====================================================
         RIDE DETAILS
      ===================================================== */

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


      /* =====================================================
         SERVICE AREA
      ===================================================== */

      serviceArea: {
        type: String,

        default: "Nalanda"
      },


      /* =====================================================
         RIDE STATUS
      ===================================================== */

      status: {
        type: String,

        default:
          "Searching for driver"
      },


      /* =====================================================
         DRIVER ASSIGNMENT
      ===================================================== */

      assignedDriverId: {
        type:
          mongoose.Schema.Types.ObjectId,

        ref: "User",

        default: null
      },

      driverId: {
        type:
          mongoose.Schema.Types.ObjectId,

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


      /* =====================================================
         DRIVER LOCATION
      ===================================================== */

      driverLocation: {
        type: locationSchema,

        default: () => ({})
      },


      /* =====================================================
         PASSENGER LOCATION
      ===================================================== */

      passengerLocation: {
        type: locationSchema,

        default: () => ({})
      },


      /* =====================================================
         DESTINATION LOCATION
      ===================================================== */

      destinationLocation: {
        type: coordSchema,

        default: () => ({})
      },


      /* =====================================================
         🔐 RIDE START CODE
      =====================================================

         Passenger ko 4 digit code milega.

         Example:
         4827

         Driver ko directly nahi milega.

      ===================================================== */

      startCode: {
        type: String,

        default: null
      },


      /* =====================================================
         🔐 START CODE VERIFIED
      ===================================================== */

      startCodeVerified: {
        type: Boolean,

        default: false
      },


      /* =====================================================
         🔐 START CODE VERIFIED TIME
      ===================================================== */

      startCodeVerifiedAt: {
        type: Date,

        default: null
      },


      /* =====================================================
         RIDE START TIME
      ===================================================== */

      startedAt: {
        type: Date,

        default: null
      },


      /* =====================================================
         RIDE COMPLETE TIME
      ===================================================== */

      completedAt: {
        type: Date,

        default: null
      },


      /* =====================================================
         RIDE CANCEL INFORMATION
      ===================================================== */

      cancelledAt: {
        type: Date,

        default: null
      },

      cancelledBy: {
        type: String,

        default: null
      },

      cancelReason: {
        type: String,

        default: null
      }

    },

    {
      timestamps: true
    }
  );


/* =========================================================
   EXPORT
========================================================= */

module.exports =
  mongoose.model(
    "Ride",
    rideSchema
  );