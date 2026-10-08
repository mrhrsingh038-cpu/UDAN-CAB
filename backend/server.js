require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");

const User = require("../model/user");
const Ride = require("../model/ride");

const app = express();

const PORT = Number(process.env.PORT) || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

const FRONTEND_DIR = path.join(__dirname, "..");

if (!MONGODB_URI) {
  console.error("❌ MONGODB_URI is missing.");
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error("❌ JWT_SECRET is missing.");
  process.exit(1);
}

app.use(
  cors({
    origin: true,
    credentials: true
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   HELPERS
========================================================= */

function normalizeRole(role) {
  if (role === "user") {
    return "passenger";
  }

  return role;
}

function publicRole(role) {
  return role;
}

function numberOrNull(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const n = Number(value);

  return Number.isFinite(n) ? n : null;
}

function distanceKm(lat1, lng1, lat2, lng2) {
  const R = 6371;

  const dLat =
    ((Number(lat2) - Number(lat1)) * Math.PI) / 180;

  const dLng =
    ((Number(lng2) - Number(lng1)) * Math.PI) / 180;

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((Number(lat1) * Math.PI) / 180) *
      Math.cos((Number(lat2) * Math.PI) / 180) *
      Math.sin(dLng / 2) ** 2;

  const c =
    2 * Math.atan2(
      Math.sqrt(a),
      Math.sqrt(1 - a)
    );

  return R * c;
}

function safeUser(user) {
  return {
    id: String(user._id),
    _id: String(user._id),
    name: user.name || "UDAN User",
    email: user.email,
    role: publicRole(user.role),
    city: user.city || "Nalanda",
    vehicleNumber: user.vehicleNumber || "",
    vehicleType: user.vehicleType || "",
    license: user.license || "",
    rating: user.rating ?? 4.8,
    online: Boolean(user.online),
    blocked: Boolean(user.blocked),
    blockedReason: user.blockedReason || "",
    location: user.location || null
  };
}

function safeRide(ride) {
  const obj =
    typeof ride.toObject === "function"
      ? ride.toObject()
      : ride;

  return {
    ...obj,
    id: String(obj._id)
  };
}

function createToken(user) {
  return jwt.sign(
    {
      id: String(user._id),
      role: user.role,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

/* =========================================================
   AUTH
========================================================= */

async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication token required."
      });
    }

    const token = header.substring(7);

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    const user = await User.findById(
      decoded.id
    );

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User account not found."
      });
    }

    if (
      user.role === "driver" &&
      user.blocked
    ) {
      return res.status(403).json({
        success: false,
        blocked: true,
        message:
          "Your driver account has been blocked by admin."
      });
    }

    req.user = user;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token."
    });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (
      !req.user ||
      !roles.includes(req.user.role)
    ) {
      return res.status(403).json({
        success: false,
        message: "Access denied."
      });
    }

    next();
  };
}

/* =========================================================
   REGISTER
========================================================= */

app.post(
  "/api/register",
  async (req, res) => {
    try {
      const {
        name,
        email,
        password,
        role,
        city,
        vehicleNumber,
        vehicleType,
        license
      } = req.body;

      if (
        !email ||
        !password ||
        !role
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Email, password and role are required."
        });
      }

      const finalRole =
        normalizeRole(role);

      if (
        !["passenger", "driver"].includes(
          finalRole
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Only passenger or driver registration is allowed."
        });
      }

      const cleanEmail =
        String(email)
          .trim()
          .toLowerCase();

      if (String(password).length < 4) {
        return res.status(400).json({
          success: false,
          message:
            "Password must contain at least 4 characters."
        });
      }

      const existing =
        await User.findOne({
          email: cleanEmail
        });

      if (existing) {
        return res.status(409).json({
          success: false,
          message:
            "This email is already registered."
        });
      }

      const hashedPassword =
        await bcrypt.hash(
          String(password),
          12
        );

      const user =
        await User.create({
          name:
            String(name || "UDAN User")
              .trim(),

          email: cleanEmail,

          password:
            hashedPassword,

          role: finalRole,

          city:
            String(
              city || "Nalanda"
            ).trim(),

          vehicleNumber:
            String(
              vehicleNumber || ""
            )
              .trim()
              .toUpperCase(),

          vehicleType:
            String(
              vehicleType || ""
            ).trim(),

          license:
            String(
              license || ""
            )
              .trim()
              .toUpperCase(),

          rating: 4.8,

          online: false,

          blocked: false
        });

      return res.status(201).json({
        success: true,
        message:
          "Registration successful.",
        user: safeUser(user)
      });
    } catch (error) {
      console.error(
        "REGISTER ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Registration failed.",
        error: error.message
      });
    }
  }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const {
        email,
        password,
        role
      } = req.body;

      if (
        !email ||
        !password ||
        !role
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Email, password and role are required."
        });
      }

      const finalRole =
        normalizeRole(role);

      const cleanEmail =
        String(email)
          .trim()
          .toLowerCase();

      const user =
        await User.findOne({
          email: cleanEmail,
          role: finalRole
        });

      if (!user) {
        return res.status(401).json({
          success: false,
          message:
            "Invalid email, password or role."
        });
      }

      if (
        user.role === "driver" &&
        user.blocked
      ) {
        return res.status(403).json({
          success: false,
          blocked: true,
          message:
            "Your driver account has been blocked by admin."
        });
      }

      const correct =
        await bcrypt.compare(
          String(password),
          user.password
        );

      if (!correct) {
        return res.status(401).json({
          success: false,
          message:
            "Invalid email, password or role."
        });
      }

      const token =
        createToken(user);

      return res.json({
        success: true,
        message:
          "Login successful.",
        token,
        user: safeUser(user)
      });
    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Login failed.",
        error: error.message
      });
    }
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/me",
  authenticate,
  (req, res) => {
    res.json({
      success: true,
      user: safeUser(req.user)
    });
  }
);

/* =========================================================
   DRIVER ONLINE/OFFLINE
========================================================= */

app.post(
  "/api/driver/status",
  authenticate,
  requireRole("driver"),
  async (req, res) => {
    try {
      const online =
        Boolean(req.body.online);

      req.user.online = online;

      if (!online) {
        req.user.location = {
          lat: null,
          lng: null,
          accuracy: null,
          updatedAt: null
        };
      }

      await req.user.save();

      res.json({
        success: true,
        online,
        message: online
          ? "You are now online."
          : "You are now offline."
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to update driver status."
      });
    }
  }
);

/* =========================================================
   GENERAL LOCATION
========================================================= */

app.post(
  "/api/location/update",
  authenticate,
  async (req, res) => {
    try {
      const lat =
        numberOrNull(
          req.body.latitude ??
            req.body.lat
        );

      const lng =
        numberOrNull(
          req.body.longitude ??
            req.body.lng
        );

      const accuracy =
        numberOrNull(
          req.body.accuracy
        );

      if (
        lat === null ||
        lng === null
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid location."
        });
      }

      req.user.location = {
        lat,
        lng,
        accuracy,
        updatedAt: new Date()
      };

      await req.user.save();

      res.json({
        success: true,
        location:
          req.user.location
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to update location."
      });
    }
  }
);

/* =========================================================
   NEARBY DRIVERS
========================================================= */

app.get(
  "/api/drivers/nearby",
  authenticate,
  requireRole("passenger"),
  async (req, res) => {
    try {
      const lat =
        numberOrNull(
          req.query.lat ??
            req.query.latitude
        );

      const lng =
        numberOrNull(
          req.query.lng ??
            req.query.longitude
        );

      const vehicleType =
        String(
          req.query.vehicleType || ""
        ).trim();

      if (
        lat === null ||
        lng === null
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Valid location is required.",
          drivers: []
        });
      }

      const city =
        String(
          req.query.serviceArea ||
            req.user.city ||
            "Nalanda"
        ).trim();

      let drivers =
        await User.find({
          role: "driver",
          online: true,
          blocked: false,
          city
        })
          .select(
            "name email vehicleType vehicleNumber rating location city online"
          )
          .lean();

      if (vehicleType) {
        drivers =
          drivers.filter(
            driver =>
              !driver.vehicleType ||
              driver.vehicleType ===
                vehicleType
          );
      }

      drivers =
        drivers
          .filter(
            driver =>
              driver.location &&
              Number.isFinite(
                Number(
                  driver.location.lat
                )
              ) &&
              Number.isFinite(
                Number(
                  driver.location.lng
                )
              )
          )
          .map(driver => ({
            ...driver,
            distanceKm:
              Number(
                distanceKm(
                  lat,
                  lng,
                  driver.location.lat,
                  driver.location.lng
                ).toFixed(2)
              )
          }))
          .sort(
            (a, b) =>
              a.distanceKm -
              b.distanceKm
          );

      res.json({
        success: true,
        drivers
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to find nearby drivers.",
        drivers: []
      });
    }
  }
);

/* =========================================================
   CREATE RIDE
========================================================= */

app.post(
  "/api/rides",
  authenticate,
  requireRole("passenger"),
  async (req, res) => {
    try {
      const {
        pickup,
        destination,
        cabType,
        fare,
        vehicleType,
        parcelType,
        parcelWeight,
        serviceArea,
        pickupLatitude,
        pickupLongitude,
        destinationLatitude,
        destinationLongitude
      } = req.body;

      if (
        !pickup ||
        !destination ||
        !cabType ||
        fare === undefined
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Pickup, destination, cab type and fare are required."
        });
      }

      const pickupLat =
        numberOrNull(
          pickupLatitude
        );

      const pickupLng =
        numberOrNull(
          pickupLongitude
        );

      const destinationLat =
        numberOrNull(
          destinationLatitude
        );

      const destinationLng =
        numberOrNull(
          destinationLongitude
        );

      const ride =
        await Ride.create({
          userId:
            req.user._id,

          pickup:
            String(pickup).trim(),

          destination:
            String(
              destination
            ).trim(),

          cabType:
            String(cabType).trim(),

          fare:
            Number(fare),

          vehicleType:
            vehicleType || null,

          parcelType:
            parcelType || null,

          parcelWeight:
            parcelWeight
              ? String(parcelWeight)
              : null,

          serviceArea:
            String(
              serviceArea ||
                req.user.city ||
                "Nalanda"
            ).trim(),

          status:
            "Searching for driver",

          passengerLocation: {
            lat: pickupLat,
            lng: pickupLng,
            accuracy: null,
            updatedAt:
              new Date()
          },

          destinationLocation: {
            lat: destinationLat,
            lng: destinationLng
          }
        });

      /* Find nearest suitable driver */

      if (
        pickupLat !== null &&
        pickupLng !== null
      ) {
        let drivers =
          await User.find({
            role: "driver",
            online: true,
            blocked: false,
            city:
              ride.serviceArea
          }).lean();

        if (ride.vehicleType) {
          drivers =
            drivers.filter(
              driver =>
                !driver.vehicleType ||
                driver.vehicleType ===
                  ride.vehicleType
            );
        }

        const candidates =
          drivers
            .filter(
              driver =>
                driver.location &&
                Number.isFinite(
                  Number(
                    driver.location.lat
                  )
                ) &&
                Number.isFinite(
                  Number(
                    driver.location.lng
                  )
                )
            )
            .map(driver => ({
              driver,
              distance:
                distanceKm(
                  pickupLat,
                  pickupLng,
                  driver.location.lat,
                  driver.location.lng
                )
            }))
            .sort(
              (a, b) =>
                a.distance -
                b.distance
            );

        if (candidates.length) {
          ride.assignedDriverId =
            candidates[0].driver._id;

          ride.assignedDistanceKm =
            Number(
              candidates[0].distance.toFixed(
                2
              )
            );

          ride.status =
            "Driver assigned";

          await ride.save();
        }
      }

      res.status(201).json({
        success: true,
        message:
          "Ride booked successfully.",
        ride: safeRide(ride)
      });
    } catch (error) {
      console.error(
        "CREATE RIDE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to book ride.",
        error: error.message
      });
    }
  }
);

/* =========================================================
   DRIVER AVAILABLE RIDES
========================================================= */

app.get(
  "/api/driver/rides",
  authenticate,
  requireRole("driver"),
  async (req, res) => {
    try {
      const rides =
        await Ride.find({
          status: {
            $in: [
              "Searching for driver",
              "Driver assigned"
            ]
          },
          driverId: null,
          $or: [
            {
              assignedDriverId:
                req.user._id
            },
            {
              assignedDriverId: null
            }
          ]
        })
          .populate(
            "userId",
            "name email city"
          )
          .sort({
            createdAt: -1
          });

      res.json({
        success: true,
        rides: rides.map(
          safeRide
        )
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to load rides.",
        rides: []
      });
    }
  }
);

/* =========================================================
   ACCEPT RIDE
========================================================= */

app.post(
  "/api/rides/:id/accept",
  authenticate,
  requireRole("driver"),
  async (req, res) => {
    try {
      const ride =
        await Ride.findById(
          req.params.id
        );

      if (!ride) {
        return res.status(404).json({
          success: false,
          message:
            "Ride not found."
        });
      }

      if (ride.driverId) {
        return res.status(409).json({
          success: false,
          message:
            "Ride already accepted."
        });
      }

      if (
        ride.assignedDriverId &&
        String(
          ride.assignedDriverId
        ) !==
          String(req.user._id)
      ) {
        return res.status(403).json({
          success: false,
          message:
            "This ride is assigned to another driver."
        });
      }

      if (
        ![
          "Searching for driver",
          "Driver assigned"
        ].includes(
          ride.status
        )
      ) {
        return res.status(409).json({
          success: false,
          message:
            "Ride is no longer available."
        });
      }

      ride.driverId =
        req.user._id;

      ride.driverName =
        req.user.name;

      ride.driverEmail =
        req.user.email;

      ride.driverVehicle =
        req.user.vehicleNumber ||
        null;

      ride.driverVehicleType =
        req.user.vehicleType ||
        null;

      ride.driverRating =
        req.user.rating ||
        null;

      ride.status =
        "Driver accepted";

      if (
        req.user.location &&
        req.user.location.lat !==
          null
      ) {
        ride.driverLocation = {
          lat:
            req.user.location.lat,
          lng:
            req.user.location.lng,
          accuracy:
            req.user.location.accuracy,
          updatedAt:
            new Date()
        };
      }

      await ride.save();

      res.json({
        success: true,
        message:
          "Ride accepted.",
        ride: safeRide(ride)
      });
    } catch (error) {
      console.error(
        "ACCEPT RIDE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to accept ride."
      });
    }
  }
);

/* =========================================================
   SINGLE RIDE
========================================================= */

app.get(
  "/api/rides/:id",
  authenticate,
  async (req, res) => {
    try {
      const ride =
        await Ride.findById(
          req.params.id
        )
          .populate(
            "userId",
            "name email city location"
          )
          .populate(
            "driverId",
            "name email vehicleNumber vehicleType rating location online"
          );

      if (!ride) {
        return res.status(404).json({
          success: false,
          message:
            "Ride not found."
        });
      }

      const passenger =
        String(
          ride.userId?._id
        ) ===
        String(req.user._id);

      const driver =
        String(
          ride.driverId?._id
        ) ===
        String(req.user._id);

      const admin =
        req.user.role ===
        "admin";

      if (
        !passenger &&
        !driver &&
        !admin
      ) {
        return res.status(403).json({
          success: false,
          message:
            "Access denied."
        });
      }

      res.json({
        success: true,
        ride: safeRide(ride)
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to load ride."
      });
    }
  }
);

/* =========================================================
   PASSENGER MY RIDES
========================================================= */

app.get(
  "/api/rides/my",
  authenticate,
  requireRole("passenger"),
  async (req, res) => {
    try {
      const rides =
        await Ride.find({
          userId:
            req.user._id
        })
          .populate(
            "driverId",
            "name email vehicleNumber vehicleType rating location"
          )
          .sort({
            createdAt: -1
          });

      res.json({
        success: true,
        rides: rides.map(
          safeRide
        )
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to load rides.",
        rides: []
      });
    }
  }
);

/* =========================================================
   START RIDE
========================================================= */

app.patch(
  "/api/rides/:id/start",
  authenticate,
  requireRole("driver"),
  async (req, res) => {
    try {
      const ride =
        await Ride.findOne({
          _id:
            req.params.id,
          driverId:
            req.user._id
        });

      if (!ride) {
        return res.status(404).json({
          success: false,
          message:
            "Ride not found."
        });
      }

      ride.status =
        "Ride started";

      await ride.save();

      res.json({
        success: true,
        ride: safeRide(ride)
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to start ride."
      });
    }
  }
);

/* =========================================================
   COMPLETE RIDE
========================================================= */

app.patch(
  "/api/rides/:id/complete",
  authenticate,
  requireRole("driver"),
  async (req, res) => {
    try {
      const ride =
        await Ride.findOne({
          _id:
            req.params.id,
          driverId:
            req.user._id
        });

      if (!ride) {
        return res.status(404).json({
          success: false,
          message:
            "Ride not found."
        });
      }

      ride.status =
        "Completed";

      await ride.save();

      res.json({
        success: true,
        ride: safeRide(ride)
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to complete ride."
      });
    }
  }
);

/* =========================================================
   CANCEL RIDE
========================================================= */

app.patch(
  "/api/rides/:id/cancel",
  authenticate,
  async (req, res) => {
    try {
      const ride =
        await Ride.findById(
          req.params.id
        );

      if (!ride) {
        return res.status(404).json({
          success: false,
          message:
            "Ride not found."
        });
      }

      const allowed =
        String(
          ride.userId
        ) ===
          String(req.user._id) ||
        String(
          ride.driverId
        ) ===
          String(req.user._id) ||
        req.user.role ===
          "admin";

      if (!allowed) {
        return res.status(403).json({
          success: false,
          message:
            "Access denied."
        });
      }

      if (
        ride.status ===
        "Completed"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Completed ride cannot be cancelled."
        });
      }

      ride.status =
        "Cancelled";

      await ride.save();

      res.json({
        success: true,
        ride: safeRide(ride)
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to cancel ride."
      });
    }
  }
);

/* =========================================================
   PASSENGER LOCATION
========================================================= */

app.patch(
  "/api/rides/:id/passenger-location",
  authenticate,
  requireRole("passenger"),
  async (req, res) => {
    try {
      const lat =
        numberOrNull(
          req.body.latitude ??
            req.body.lat
        );

      const lng =
        numberOrNull(
          req.body.longitude ??
            req.body.lng
        );

      if (
        lat === null ||
        lng === null
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid location."
        });
      }

      const ride =
        await Ride.findOne({
          _id:
            req.params.id,
          userId:
            req.user._id
        });

      if (!ride) {
        return res.status(404).json({
          success: false,
          message:
            "Ride not found."
        });
      }

      ride.passengerLocation = {
        lat,
        lng,
        accuracy:
          numberOrNull(
            req.body.accuracy
          ),
        updatedAt:
          new Date()
      };

      await ride.save();

      res.json({
        success: true,
        location:
          ride.passengerLocation
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to update passenger location."
      });
    }
  }
);

/* =========================================================
   DRIVER LOCATION
========================================================= */

app.patch(
  "/api/rides/:id/driver-location",
  authenticate,
  requireRole("driver"),
  async (req, res) => {
    try {
      const lat =
        numberOrNull(
          req.body.latitude ??
            req.body.lat
        );

      const lng =
        numberOrNull(
          req.body.longitude ??
            req.body.lng
        );

      if (
        lat === null ||
        lng === null
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid location."
        });
      }

      const ride =
        await Ride.findOne({
          _id:
            req.params.id,
          driverId:
            req.user._id
        });

      if (!ride) {
        return res.status(404).json({
          success: false,
          message:
            "Ride not found."
        });
      }

      ride.driverLocation = {
        lat,
        lng,
        accuracy:
          numberOrNull(
            req.body.accuracy
          ),
        updatedAt:
          new Date()
      };

      await ride.save();

      req.user.location =
        ride.driverLocation;

      req.user.online = true;

      await req.user.save();

      res.json({
        success: true,
        location:
          ride.driverLocation
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to update driver location."
      });
    }
  }
);

/* =========================================================
   LIVE LOCATION
========================================================= */

app.get(
  "/api/rides/:id/live-location",
  authenticate,
  async (req, res) => {
    try {
      const ride =
        await Ride.findById(
          req.params.id
        );

      if (!ride) {
        return res.status(404).json({
          success: false,
          message:
            "Ride not found."
        });
      }

      const allowed =
        String(
          ride.userId
        ) ===
          String(req.user._id) ||
        String(
          ride.driverId
        ) ===
          String(req.user._id) ||
        req.user.role ===
          "admin";

      if (!allowed) {
        return res.status(403).json({
          success: false,
          message:
            "Access denied."
        });
      }

      res.json({
        success: true,
        rideId: ride._id,
        status: ride.status,
        passengerLocation:
          ride.passengerLocation,
        driverLocation:
          ride.driverLocation
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to load live location."
      });
    }
  }
);

/* =========================================================
   DRIVER MY RIDES
========================================================= */

app.get(
  "/api/driver/my-rides",
  authenticate,
  requireRole("driver"),
  async (req, res) => {
    try {
      const rides =
        await Ride.find({
          driverId:
            req.user._id
        })
          .populate(
            "userId",
            "name email city"
          )
          .sort({
            createdAt: -1
          });

      res.json({
        success: true,
        rides: rides.map(
          safeRide
        )
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to load driver rides.",
        rides: []
      });
    }
  }
);

/* =========================================================
   ADMIN - PASSENGERS
========================================================= */

app.get(
  "/api/admin/passengers",
  authenticate,
  requireRole("admin"),
  async (req, res) => {
    const passengers =
      await User.find({
        role: "passenger"
      })
        .select("-password")
        .sort({
          createdAt: -1
        })
        .lean();

    res.json({
      success: true,
      passengers
    });
  }
);

/* =========================================================
   ADMIN - DRIVERS
========================================================= */

app.get(
  "/api/admin/drivers",
  authenticate,
  requireRole("admin"),
  async (req, res) => {
    const drivers =
      await User.find({
        role: "driver"
      })
        .select("-password")
        .sort({
          createdAt: -1
        })
        .lean();

    res.json({
      success: true,
      drivers
    });
  }
);

/* =========================================================
   ADMIN - RIDES
========================================================= */

app.get(
  "/api/admin/rides",
  authenticate,
  requireRole("admin"),
  async (req, res) => {
    const rides =
      await Ride.find({})
        .populate(
          "userId",
          "name email city"
        )
        .populate(
          "driverId",
          "name email vehicleNumber vehicleType rating online"
        )
        .sort({
          createdAt: -1
        });

    res.json({
      success: true,
      rides: rides.map(
        safeRide
      )
    });
  }
);

/* =========================================================
   ADMIN - STATS
========================================================= */

app.get(
  "/api/admin/stats",
  authenticate,
  requireRole("admin"),
  async (req, res) => {
    try {
      const [
        totalUsers,
        totalDrivers,
        blockedDrivers,
        totalRides,
        completedRides,
        activeRides
      ] =
        await Promise.all([
          User.countDocuments({
            role: "passenger"
          }),

          User.countDocuments({
            role: "driver"
          }),

          User.countDocuments({
            role: "driver",
            blocked: true
          }),

          Ride.countDocuments({}),

          Ride.countDocuments({
            status: "Completed"
          }),

          Ride.countDocuments({
            status: {
              $nin: [
                "Completed",
                "Cancelled"
              ]
            }
          })
        ]);

      res.json({
        success: true,
        stats: {
          totalUsers,
          totalDrivers,
          blockedDrivers,
          totalRides,
          completedRides,
          activeRides
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to load statistics."
      });
    }
  }
);

/* =========================================================
   ADMIN - BLOCK
========================================================= */

app.patch(
  "/api/admin/drivers/:id/block",
  authenticate,
  requireRole("admin"),
  async (req, res) => {
    try {
      const driver =
        await User.findOneAndUpdate(
          {
            _id:
              req.params.id,
            role: "driver"
          },
          {
            $set: {
              blocked: true,
              blockedReason:
                req.body.reason ||
                "Blocked by admin.",
              blockedAt:
                new Date(),
              online: false
            }
          },
          {
            new: true
          }
        ).select("-password");

      if (!driver) {
        return res.status(404).json({
          success: false,
          message:
            "Driver not found."
        });
      }

      res.json({
        success: true,
        message:
          "Driver blocked.",
        driver
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to block driver."
      });
    }
  }
);

/* =========================================================
   ADMIN - UNBLOCK
========================================================= */

app.patch(
  "/api/admin/drivers/:id/unblock",
  authenticate,
  requireRole("admin"),
  async (req, res) => {
    try {
      const driver =
        await User.findOneAndUpdate(
          {
            _id:
              req.params.id,
            role: "driver"
          },
          {
            $set: {
              blocked: false,
              blockedReason: "",
              blockedAt: null
            }
          },
          {
            new: true
          }
        ).select("-password");

      if (!driver) {
        return res.status(404).json({
          success: false,
          message:
            "Driver not found."
        });
      }

      res.json({
        success: true,
        message:
          "Driver unblocked.",
        driver
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to unblock driver."
      });
    }
  }
);

/* =========================================================
   ADMIN - REMOVE DRIVER
========================================================= */

app.delete(
  "/api/admin/drivers/:id",
  authenticate,
  requireRole("admin"),
  async (req, res) => {
    try {
      const driver =
        await User.findOne({
          _id:
            req.params.id,
          role: "driver"
        });

      if (!driver) {
        return res.status(404).json({
          success: false,
          message:
            "Driver not found."
        });
      }

      const activeRide =
        await Ride.findOne({
          driverId:
            driver._id,
          status: {
            $nin: [
              "Completed",
              "Cancelled"
            ]
          }
        });

      if (activeRide) {
        return res.status(409).json({
          success: false,
          message:
            "Driver has an active ride."
        });
      }

      await User.deleteOne({
        _id:
          driver._id
      });

      res.json({
        success: true,
        message:
          "Driver removed."
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to remove driver."
      });
    }
  }
);

/* =========================================================
   SERVICE AREAS
========================================================= */

app.get(
  "/api/service-areas",
  (req, res) => {
    res.json({
      success: true,
      areas: [
        {
          name: "Nalanda",
          active: true
        }
      ]
    });
  }
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      success: true,
      message:
        "UDAN CAB server is running.",
      database:
        mongoose.connection.readyState === 1
          ? "connected"
          : "disconnected",
      time:
        new Date().toISOString()
    });
  }
);

/* =========================================================
   FRONTEND
========================================================= */

app.use(
  express.static(
    FRONTEND_DIR,
    {
      extensions: ["html"]
    }
  )
);

app.get(
  "/",
  (req, res) => {
    res.sendFile(
      path.join(
        FRONTEND_DIR,
        "index.html"
      )
    );
  }
);

app.get(
  "/login.html",
  (req, res) => {
    res.sendFile(
      path.join(
        FRONTEND_DIR,
        "login.html"
      )
    );
  }
);

app.get(
  "/dashboard.html",
  (req, res) => {
    res.sendFile(
      path.join(
        FRONTEND_DIR,
        "dashboard.html"
      )
    );
  }
);

app.get(
  "/driver-dashboard.html",
  (req, res) => {
    res.sendFile(
      path.join(
        FRONTEND_DIR,
        "driver-dashboard.html"
      )
    );
  }
);

app.get(
  "/admin.html",
  (req, res) => {
    res.sendFile(
      path.join(
        FRONTEND_DIR,
        "admin.html"
      )
    );
  }
);

app.get(
  "/parcel.html",
  (req, res) => {
    res.sendFile(
      path.join(
        FRONTEND_DIR,
        "parcel.html"
      )
    );
  }
);

/* =========================================================
   API 404
========================================================= */

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      success: false,
      message:
        "API route not found.",
      path:
        req.originalUrl
    });
  }
);

/* =========================================================
   GLOBAL ERROR
========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      "GLOBAL ERROR:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      success: false,
      message:
        "Internal server error."
    });
  }
);

/* =========================================================
   DATABASE + SERVER
========================================================= */

async function startServer() {
  try {
    await mongoose.connect(
      MONGODB_URI
    );

    console.log(
      "✅ MongoDB connected."
    );

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `🚕 UDAN CAB running on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      "❌ MongoDB connection failed:"
    );

    console.error(
      error.message
    );

    process.exit(1);
  }
}

startServer();