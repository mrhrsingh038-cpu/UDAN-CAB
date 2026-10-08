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
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return null;
  }

  const n = Number(value);

  return Number.isFinite(n)
    ? n
    : null;
}

function distanceKm(
  lat1,
  lng1,
  lat2,
  lng2
) {
  const R = 6371;

  const dLat =
    ((Number(lat2) -
      Number(lat1)) *
      Math.PI) /
    180;

  const dLng =
    ((Number(lng2) -
      Number(lng1)) *
      Math.PI) /
    180;

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(
      (Number(lat1) *
        Math.PI) /
        180
    ) *
      Math.cos(
        (Number(lat2) *
          Math.PI) /
          180
      ) *
      Math.sin(dLng / 2) ** 2;

  const c =
    2 *
    Math.atan2(
      Math.sqrt(a),
      Math.sqrt(1 - a)
    );

  return R * c;
}

function safeUser(user) {
  return {
    id: String(user._id),

    _id: String(user._id),

    name:
      user.name ||
      "UDAN User",

    email:
      user.email,

    role:
      publicRole(
        user.role
      ),

    city:
      user.city ||
      "Nalanda",

    vehicleNumber:
      user.vehicleNumber ||
      "",

    vehicleType:
      user.vehicleType ||
      "",

    license:
      user.license ||
      "",

    rating:
      user.rating ??
      4.8,

    online:
      Boolean(
        user.online
      ),

    blocked:
      Boolean(
        user.blocked
      ),

    blockedReason:
      user.blockedReason ||
      "",

    location:
      user.location ||
      null
  };
}


/*
 * =========================================================
 * SAFE RIDE
 * =========================================================
 *
 * IMPORTANT:
 *
 * Driver ko passenger ka startCode nahi dikhana hai.
 *
 * Passenger ke liye jab zarurat hogi tab:
 *
 * safeRide(ride, true)
 *
 * use karenge.
 */

function safeRide(
  ride,
  includeStartCode = false
) {
  const obj =
    typeof ride.toObject ===
    "function"
      ? ride.toObject()
      : ride;

  const {
    startCode,
    ...safeData
  } = obj;

  const result = {
    ...safeData,

    id: String(
      obj._id
    )
  };

  /*
   * 🔐 ONLY PASSENGER
   */
  if (
    includeStartCode
  ) {
    result.startCode =
      startCode ||
      null;
  }

  return result;
}


function createToken(user) {
  return jwt.sign(
    {
      id: String(
        user._id
      ),

      role:
        user.role,

      email:
        user.email
    },

    JWT_SECRET,

    {
      expiresIn:
        "7d"
    }
  );
}


/* =========================================================
   AUTH
========================================================= */

async function authenticate(
  req,
  res,
  next
) {
  try {

    const header =
      req.headers
        .authorization ||
      "";

    if (
      !header.startsWith(
        "Bearer "
      )
    ) {
      return res
        .status(401)
        .json({
          success: false,

          message:
            "Authentication token required."
        });
    }

    const token =
      header.substring(7);

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    const user =
      await User.findById(
        decoded.id
      );

    if (!user) {
      return res
        .status(401)
        .json({
          success: false,

          message:
            "User account not found."
        });
    }

    if (
      user.role ===
        "driver" &&
      user.blocked
    ) {
      return res
        .status(403)
        .json({
          success: false,

          blocked: true,

          message:
            "Your driver account has been blocked by admin."
        });
    }

    req.user =
      user;

    next();

  } catch (error) {

    return res
      .status(401)
      .json({
        success: false,

        message:
          "Invalid or expired token."
      });
  }
}


function requireRole(
  ...roles
) {
  return (
    req,
    res,
    next
  ) => {

    if (
      !req.user ||
      !roles.includes(
        req.user.role
      )
    ) {
      return res
        .status(403)
        .json({
          success: false,

          message:
            "Access denied."
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
  async (
    req,
    res
  ) => {

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
        return res
          .status(400)
          .json({
            success: false,

            message:
              "Email, password and role are required."
          });
      }

      const finalRole =
        normalizeRole(
          role
        );

      if (
        ![
          "passenger",
          "driver"
        ].includes(
          finalRole
        )
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "Only passenger or driver registration is allowed."
          });
      }

      const cleanEmail =
        String(
          email
        )
          .trim()
          .toLowerCase();

      if (
        String(
          password
        ).length < 4
      ) {
        return res
          .status(400)
          .json({
            success: false,

            message:
              "Password must contain at least 4 characters."
          });
      }

      const existing =
        await User.findOne({
          email:
            cleanEmail
        });

      if (existing) {
        return res
          .status(409)
          .json({
            success: false,

            message:
              "This email is already registered."
          });
      }

      const hashedPassword =
        await bcrypt.hash(
          String(
            password
          ),
          12
        );

      const user =
        await User.create({

          name:
            String(
              name ||
                "UDAN User"
            ).trim(),

          email:
            cleanEmail,

          password:
            hashedPassword,

          role:
            finalRole,

          city:
            String(
              city ||
                "Nalanda"
            ).trim(),

          vehicleNumber:
            String(
              vehicleNumber ||
                ""
            )
              .trim()
              .toUpperCase(),

          vehicleType:
            String(
              vehicleType ||
                ""
            ).trim(),

          license:
            String(
              license ||
                ""
            )
              .trim()
              .toUpperCase(),

          rating:
            4.8,

          online:
            false,

          blocked:
            false
        });

      return res
        .status(201)
        .json({
          success: true,

          message:
            "Registration successful.",

          user:
            safeUser(
              user
            )
        });

    } catch (error) {

      console.error(
        "REGISTER ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Registration failed.",

          error:
            error.message
        });
    }
  }
);


/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/login",
  async (
    req,
    res
  ) => {

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
        return res
          .status(400)
          .json({
            success: false,

            message:
              "Email, password and role are required."
          });
      }

      const finalRole =
        normalizeRole(
          role
        );

      const cleanEmail =
        String(
          email
        )
          .trim()
          .toLowerCase();

      const user =
        await User.findOne({
          email:
            cleanEmail,

          role:
            finalRole
        });

      if (!user) {
        return res
          .status(401)
          .json({
            success: false,

            message:
              "Invalid email, password or role."
          });
      }

      if (
        user.role ===
          "driver" &&
        user.blocked
      ) {
        return res
          .status(403)
          .json({
            success: false,

            blocked: true,

            message:
              "Your driver account has been blocked by admin."
          });
      }

      const correct =
        await bcrypt.compare(
          String(
            password
          ),
          user.password
        );

      if (!correct) {
        return res
          .status(401)
          .json({
            success: false,

            message:
              "Invalid email, password or role."
          });
      }

      const token =
        createToken(
          user
        );

      return res.json({
        success: true,

        message:
          "Login successful.",

        token,

        user:
          safeUser(
            user
          )
      });

    } catch (error) {

      console.error(
        "LOGIN ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Login failed.",

          error:
            error.message
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
  (
    req,
    res
  ) => {

    res.json({
      success: true,

      user:
        safeUser(
          req.user
        )
    });

  }
);


/* =========================================================
   DRIVER ONLINE/OFFLINE
========================================================= */

app.post(
  "/api/driver/status",
  authenticate,
  requireRole(
    "driver"
  ),

  async (
    req,
    res
  ) => {

    try {

      const online =
        Boolean(
          req.body.online
        );

      req.user.online =
        online;

      if (!online) {

        req.user.location = {
          lat:
            null,

          lng:
            null,

          accuracy:
            null,

          updatedAt:
            null
        };
      }

      await req.user.save();

      res.json({

        success: true,

        online,

        message:
          online
            ? "You are now online."
            : "You are now offline."
      });

    } catch (error) {

      res
        .status(500)
        .json({

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

  async (
    req,
    res
  ) => {

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

        return res
          .status(400)
          .json({

            success: false,

            message:
              "Invalid location."
          });
      }

      req.user.location = {

        lat,

        lng,

        accuracy,

        updatedAt:
          new Date()
      };

      await req.user.save();

      res.json({

        success: true,

        location:
          req.user.location
      });

    } catch (error) {

      res
        .status(500)
        .json({

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
          req.query.vehicleType ||
            ""
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

      const MAX_RADIUS_KM = 10;

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
          .filter(
            driver =>
              driver.distanceKm <=
              MAX_RADIUS_KM
          )
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

      console.error(
        "NEARBY DRIVER ERROR:",
        error
      );

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


      /*
       * =====================================================
       * 🔐 RIDE START CODE
       * =====================================================
       *
       * Har new ride ke liye ek fresh
       * 4 digit code generate hoga.
       *
       * Example:
       * 4827
       *
       * Passenger ko baad me ye code milega.
       * Driver ko code directly nahi bheja jayega.
       */

      const startCode =
        String(
          Math.floor(
            1000 +
              Math.random() *
                9000
          )
        );


      /*
       * IMPORTANT:
       *
       * Ride ko automatically kisi driver
       * ko assign nahi karna hai.
       *
       * Driver dashboard khud nearby ride
       * filter karega:
       *
       * 1. Same area
       * 2. Same vehicle
       * 3. Maximum 10 KM
       * 4. Driver online
       * 5. Driver GPS available
       */

      const ride =
        await Ride.create({

          userId:
            req.user._id,

          pickup:
            String(
              pickup
            ).trim(),

          destination:
            String(
              destination
            ).trim(),

          cabType:
            String(
              cabType
            ).trim(),

          fare:
            Number(fare),

          vehicleType:
            vehicleType ||
            null,

          parcelType:
            parcelType ||
            null,

          parcelWeight:
            parcelWeight
              ? String(
                  parcelWeight
                )
              : null,

          serviceArea:
            String(
              serviceArea ||
                req.user.city ||
                "Nalanda"
            ).trim(),

          status:
            "Searching for driver",


          /*
           * 🔐 START CODE DATA
           */

          startCode:
            startCode,

          startCodeVerified:
            false,

          startCodeVerifiedAt:
            null,


          passengerLocation: {

            lat:
              pickupLat,

            lng:
              pickupLng,

            accuracy:
              null,

            updatedAt:
              new Date()
          },

          destinationLocation: {

            lat:
              destinationLat,

            lng:
              destinationLng
          }
        });


      return res.status(201).json({

        success: true,

        message:
          "Ride booked successfully. Searching for nearby drivers.",

        ride:
          safeRide(ride)

      });

    } catch (error) {

      console.error(
        "CREATE RIDE ERROR:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "Unable to book ride.",

        error:
          error.message

      });
    }
  }
);


/* =========================================================
   DRIVER AVAILABLE RIDES

   ONLY:
   - SAME AREA
   - SAME VEHICLE TYPE
   - WITHIN 10 KM
   - DRIVER ONLINE
   - DRIVER GPS AVAILABLE
========================================================= */

async function getDriverAvailableRides(
  req,
  res
) {

  try {

    const driver =
      await User.findById(
        req.user._id
      ).lean();


    if (!driver) {

      return res.status(404).json({

        success: false,

        message:
          "Driver not found.",

        rides: []

      });
    }


    if (
      driver.role !==
      "driver"
    ) {

      return res.status(403).json({

        success: false,

        message:
          "Driver access required.",

        rides: []

      });
    }


    if (
      driver.blocked
    ) {

      return res.status(403).json({

        success: false,

        message:
          "Driver is blocked.",

        rides: []

      });
    }


    /*
     * DRIVER MUST BE ONLINE
     */

    if (
      !driver.online
    ) {

      return res.json({

        success: true,

        rides: []

      });
    }


    /*
     * DRIVER GPS MUST BE AVAILABLE
     */

    if (
      !driver.location ||
      !Number.isFinite(
        Number(
          driver.location.lat
        )
      ) ||
      !Number.isFinite(
        Number(
          driver.location.lng
        )
      )
    ) {

      return res.json({

        success: true,

        rides: []

      });
    }


    const driverLat =
      Number(
        driver.location.lat
      );

    const driverLng =
      Number(
        driver.location.lng
      );


    /*
     * MAXIMUM DISTANCE
     */

    const MAX_RADIUS_KM = 10;


    /*
     * DRIVER AREA
     */

    const driverArea =
      String(
        driver.city ||
          ""
      )
        .trim()
        .toLowerCase();


    /*
     * First get only unaccepted rides.
     *
     * IMPORTANT:
     * assignedDriverId is NOT required anymore.
     */

    const rides =
      await Ride.find({

        status:
          "Searching for driver",

        driverId:
          null

      })
        .populate(
          "userId",
          "name email city"
        )
        .sort({
          createdAt:
            -1
        })
        .lean();


    const nearbyRides = [];


    for (
      const ride of rides
    ) {


      /*
       * =========================================
       * 1. PICKUP GPS CHECK
       * =========================================
       */

      if (
        !ride.passengerLocation ||
        !Number.isFinite(
          Number(
            ride
              .passengerLocation
              .lat
          )
        ) ||
        !Number.isFinite(
          Number(
            ride
              .passengerLocation
              .lng
          )
        )
      ) {

        continue;
      }


      const pickupLat =
        Number(
          ride
            .passengerLocation
            .lat
        );

      const pickupLng =
        Number(
          ride
            .passengerLocation
            .lng
        );


      /*
       * =========================================
       * 2. AREA CHECK
       * =========================================
       */

      const rideArea =
        String(
          ride.serviceArea ||
            (
              ride.userId &&
              ride.userId.city
            ) ||
            ""
        )
          .trim()
          .toLowerCase();


      if (
        rideArea &&
        driverArea &&
        rideArea !==
          driverArea
      ) {

        continue;
      }


      /*
       * =========================================
       * 3. VEHICLE TYPE CHECK
       * =========================================
       *
       * Agar passenger ne vehicle type select
       * kiya hai aur driver ka vehicle type
       * alag hai to ride nahi dikhegi.
       */

      if (
        ride.vehicleType &&
        driver.vehicleType &&
        String(
          ride.vehicleType
        )
          .trim()
          .toLowerCase() !==
          String(
            driver.vehicleType
          )
            .trim()
            .toLowerCase()
      ) {

        continue;
      }


      /*
       * =========================================
       * 4. DISTANCE CALCULATION
       * =========================================
       */

      const distance =
        distanceKm(

          driverLat,
          driverLng,

          pickupLat,
          pickupLng

        );


      /*
       * =========================================
       * 5. ONLY 10 KM RADIUS
       * =========================================
       */

      if (
        distance >
        MAX_RADIUS_KM
      ) {

        continue;
      }


      /*
       * =========================================
       * 6. ELIGIBLE RIDE
       * =========================================
       */

      nearbyRides.push({

        ...ride,

        driverDistanceKm:
          Number(
            distance.toFixed(
              2
            )
          )

      });
    }


    /*
     * NEAREST RIDE FIRST
     */

    nearbyRides.sort(
      (
        a,
        b
      ) =>
        Number(
          a.driverDistanceKm
        ) -
        Number(
          b.driverDistanceKm
        )
    );


    return res.json({

      success: true,

      rides:
        nearbyRides

    });


  } catch (error) {

    console.error(
      "DRIVER RIDES ERROR:",
      error
    );

    return res.status(
      500
    ).json({

      success: false,

      message:
        "Unable to load nearby rides.",

      rides: []

    });
  }
}


app.get(
  "/api/driver/rides",
  authenticate,
  requireRole("driver"),
  getDriverAvailableRides
);
/* =========================================================
   ALL RIDES
========================================================= */

app.get(
  "/api/rides",
  authenticate,
  async (req, res) => {
    try {

      let filter = {};

      /*
       * PASSENGER:
       * Sirf apni rides
       */
      if (
        req.user.role ===
        "passenger"
      ) {

        filter = {
          userId:
            req.user._id
        };

      }

      /*
       * DRIVER:
       * Sirf eligible rides.
       *
       * IMPORTANT:
       * Yahan bhi unrestricted rides
       * return nahi hongi.
       */
      else if (
        req.user.role ===
        "driver"
      ) {

        const driver =
          await User.findById(
            req.user._id
          ).lean();

        if (
          !driver ||
          !driver.online ||
          driver.blocked ||
          !driver.location
        ) {
          return res.json({
            success: true,
            rides: []
          });
        }

        const driverLat =
          Number(
            driver.location.lat
          );

        const driverLng =
          Number(
            driver.location.lng
          );

        if (
          !Number.isFinite(
            driverLat
          ) ||
          !Number.isFinite(
            driverLng
          )
        ) {
          return res.json({
            success: true,
            rides: []
          });
        }

        const MAX_RADIUS_KM =
          10;

        const rides =
          await Ride.find({
            status:
              "Searching for driver",

            driverId:
              null
          })
            .populate(
              "userId",
              "name email city"
            )
            .sort({
              createdAt:
                -1
            })
            .lean();

        const eligible =
          [];

        const driverArea =
          String(
            driver.city ||
              ""
          )
            .trim()
            .toLowerCase();

        for (
          const ride of rides
        ) {

          if (
            !ride.passengerLocation
          ) {
            continue;
          }

          const pickupLat =
            Number(
              ride
                .passengerLocation
                .lat
            );

          const pickupLng =
            Number(
              ride
                .passengerLocation
                .lng
            );

          if (
            !Number.isFinite(
              pickupLat
            ) ||
            !Number.isFinite(
              pickupLng
            )
          ) {
            continue;
          }

          const rideArea =
            String(
              ride.serviceArea ||
                (
                  ride.userId &&
                  ride.userId.city
                ) ||
                ""
            )
              .trim()
              .toLowerCase();

          if (
            rideArea &&
            driverArea &&
            rideArea !==
              driverArea
          ) {
            continue;
          }

          if (
            ride.vehicleType &&
            driver.vehicleType &&
            String(
              ride.vehicleType
            )
              .trim()
              .toLowerCase() !==
              String(
                driver.vehicleType
              )
                .trim()
                .toLowerCase()
          ) {
            continue;
          }

          const distance =
            distanceKm(
              driverLat,
              driverLng,
              pickupLat,
              pickupLng
            );

          if (
            distance >
            MAX_RADIUS_KM
          ) {
            continue;
          }

          eligible.push({
            ...ride,

            driverDistanceKm:
              Number(
                distance.toFixed(
                  2
                )
              )
          });
        }

        return res.json({
          success: true,
          rides:
            eligible
        });
      }

      const rides =
        await Ride.find(
          filter
        )
          .populate(
            "userId",
            "name email city"
          )
          .populate(
            "driverId",
            "name email vehicleNumber vehicleType rating location online blocked"
          )
          .sort({
            createdAt:
              -1
          });

      return res.json({
        success: true,
        rides
      });

    } catch (error) {

      console.error(
        "GET RIDES ERROR:",
        error
      );

      return res.status(
        500
      ).json({
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

      /*
       * GET FRESH DRIVER DATA
       */
      const driver =
        await User.findById(
          req.user._id
        );

      if (!driver) {

        return res.status(
          404
        ).json({

          success: false,

          message:
            "Driver not found."

        });
      }


      /*
       * BLOCKED DRIVER
       */

      if (
        driver.blocked
      ) {

        return res.status(
          403
        ).json({

          success: false,

          blocked: true,

          message:
            "Driver is blocked."

        });
      }


      /*
       * DRIVER MUST BE ONLINE
       */

      if (
        !driver.online
      ) {

        return res.status(
          403
        ).json({

          success: false,

          message:
            "Please go online before accepting a ride."

        });
      }


      /*
       * DRIVER GPS
       */

      if (
        !driver.location ||
        !Number.isFinite(
          Number(
            driver.location.lat
          )
        ) ||
        !Number.isFinite(
          Number(
            driver.location.lng
          )
        )
      ) {

        return res.status(
          400
        ).json({

          success: false,

          message:
            "Driver location is not available. Please enable GPS."

        });
      }


      /*
       * GET RIDE
       */

      const ride =
        await Ride.findById(
          req.params.id
        );

      if (!ride) {

        return res.status(
          404
        ).json({

          success: false,

          message:
            "Ride not found."

        });
      }


      /*
       * ALREADY ACCEPTED
       */

      if (
        ride.driverId
      ) {

        return res.status(
          409
        ).json({

          success: false,

          message:
            "Ride already accepted."

        });
      }


      /*
       * RIDE STATUS
       */

      if (
        ride.status !==
        "Searching for driver"
      ) {

        return res.status(
          409
        ).json({

          success: false,

          message:
            "Ride is no longer available."

        });
      }


      /*
       * PASSENGER PICKUP GPS
       */

      if (
        !ride.passengerLocation ||
        !Number.isFinite(
          Number(
            ride
              .passengerLocation
              .lat
          )
        ) ||
        !Number.isFinite(
          Number(
            ride
              .passengerLocation
              .lng
          )
        )
      ) {

        return res.status(
          400
        ).json({

          success: false,

          message:
            "Passenger pickup location is unavailable."

        });
      }


      /*
       * =========================================
       * AREA CHECK
       * =========================================
       */

      const rideArea =
        String(
          ride.serviceArea ||
            ""
        )
          .trim()
          .toLowerCase();

      const driverArea =
        String(
          driver.city ||
            ""
        )
          .trim()
          .toLowerCase();


      if (
        rideArea &&
        driverArea &&
        rideArea !==
          driverArea
      ) {

        return res.status(
          403
        ).json({

          success: false,

          message:
            "This ride is outside your service area."

        });
      }


      /*
       * =========================================
       * VEHICLE CHECK
       * =========================================
       */

      if (
        ride.vehicleType &&
        driver.vehicleType &&
        String(
          ride.vehicleType
        )
          .trim()
          .toLowerCase() !==
          String(
            driver.vehicleType
          )
            .trim()
            .toLowerCase()
      ) {

        return res.status(
          403
        ).json({

          success: false,

          message:
            "Vehicle type does not match this ride."

        });
      }


      /*
       * =========================================
       * DISTANCE CHECK
       * =========================================
       */

      const driverLat =
        Number(
          driver.location.lat
        );

      const driverLng =
        Number(
          driver.location.lng
        );

      const pickupLat =
        Number(
          ride
            .passengerLocation
            .lat
        );

      const pickupLng =
        Number(
          ride
            .passengerLocation
            .lng
        );

      const distance =
        distanceKm(
          driverLat,
          driverLng,
          pickupLat,
          pickupLng
        );

      const MAX_RADIUS_KM =
        10;


      if (
        distance >
        MAX_RADIUS_KM
      ) {

        return res.status(
          403
        ).json({

          success: false,

          message:
            `Passenger is ${distance.toFixed(
              2
            )} KM away. Ride is available only within 10 KM.`

        });
      }


      /*
       * =========================================
       * ACCEPT RIDE
       * =========================================
       */

      ride.driverId =
        driver._id;

      ride.driverName =
        driver.name;

      ride.driverEmail =
        driver.email;

      ride.driverVehicle =
        driver.vehicleNumber ||
        null;

      ride.driverVehicleType =
        driver.vehicleType ||
        null;

      ride.driverRating =
        driver.rating ||
        null;

      ride.status =
        "Driver accepted";


      ride.driverLocation = {

        lat:
          driverLat,

        lng:
          driverLng,

        accuracy:
          driver.location.accuracy,

        updatedAt:
          new Date()

      };


      await ride.save();


      return res.json({

        success: true,

        message:
          "Ride accepted successfully.",

        ride:
          safeRide(ride)

      });

    } catch (error) {

      console.error(
        "ACCEPT RIDE ERROR:",
        error
      );

      return res.status(
        500
      ).json({

        success: false,

        message:
          "Unable to accept ride.",

        error:
          error.message

      });
    }
  }
);
/* =========================================================
   DRIVER LOCATION UPDATE FOR ACTIVE RIDE
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
            "Valid driver location is required."
        });
      }

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

      if (
        !ride.driverId ||
        String(
          ride.driverId
        ) !==
          String(
            req.user._id
          )
      ) {
        return res.status(403).json({
          success: false,
          message:
            "You are not the driver of this ride."
        });
      }

      ride.driverLocation = {
        lat,
        lng,
        accuracy,
        updatedAt:
          new Date()
      };

      await ride.save();

      /*
       * Driver ki latest location bhi
       * User document me save karo.
       */

      req.user.location = {
        lat,
        lng,
        accuracy,
        updatedAt:
          new Date()
      };

      req.user.online =
        true;

      await req.user.save();

      return res.json({
        success: true,
        message:
          "Driver location updated.",
        location:
          ride.driverLocation
      });

    } catch (error) {

      console.error(
        "DRIVER LOCATION ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to update driver location."
      });
    }
  }
);


/* =========================================================
   PASSENGER LIVE LOCATION
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
            "Valid passenger location is required."
        });
      }

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

      if (
        String(
          ride.userId
        ) !==
          String(
            req.user._id
          )
      ) {
        return res.status(403).json({
          success: false,
          message:
            "You cannot update this ride."
        });
      }

      ride.passengerLocation = {
        lat,
        lng,
        accuracy,
        updatedAt:
          new Date()
      };

      await ride.save();

      return res.json({
        success: true,
        message:
          "Passenger location updated.",
        location:
          ride.passengerLocation
      });

    } catch (error) {

      console.error(
        "PASSENGER LOCATION ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to update passenger location."
      });
    }
  }
);


/* =========================================================
   GET SINGLE RIDE
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
            "name email city"
          )
          .populate(
            "driverId",
            "name email vehicleNumber vehicleType rating location online blocked"
          );

      if (!ride) {
        return res.status(404).json({
          success: false,
          message:
            "Ride not found."
        });
      }


      /*
       * Passenger only apni ride
       * dekh sakta hai.
       */

      if (
        req.user.role ===
          "passenger" &&
        String(
          ride.userId?._id ||
            ride.userId
        ) !==
          String(
            req.user._id
          )
      ) {
        return res.status(403).json({
          success: false,
          message:
            "Access denied."
        });
      }


      /*
       * Driver sirf apni accepted ride
       * dekh sakta hai.
       */

      if (
        req.user.role ===
          "driver" &&
        ride.driverId &&
        String(
          ride.driverId._id ||
            ride.driverId
        ) !==
          String(
            req.user._id
          )
      ) {
        return res.status(403).json({
          success: false,
          message:
            "Access denied."
        });
      }


      /*
       * 🔐 START CODE
       *
       * Passenger ko code milega.
       * Driver ko code nahi milega.
       */

      const isPassenger =
        req.user.role ===
          "passenger" &&
        String(
          ride.userId?._id ||
            ride.userId
        ) ===
          String(
            req.user._id
          );


      return res.json({

        success: true,

        ride:
          safeRide(
            ride,
            isPassenger
          )

      });

    } catch (error) {

      console.error(
        "GET RIDE ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load ride."
      });
    }
  }
);


/* =========================================================
   🔐 START RIDE
   PASSENGER START CODE REQUIRED
========================================================= */

app.patch(
  "/api/rides/:id/start",
  authenticate,
  requireRole("driver"),

  async (req, res) => {

    try {

      /*
       * GET RIDE
       */

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


      /*
       * DRIVER OWNERSHIP CHECK
       */

      if (
        !ride.driverId ||
        String(
          ride.driverId
        ) !==
          String(
            req.user._id
          )
      ) {

        return res.status(403).json({

          success: false,

          message:
            "You are not assigned to this ride."

        });
      }


      /*
       * RIDE MUST BE ACCEPTED
       */

      if (
        ride.status !==
        "Driver accepted"
      ) {

        return res.status(409).json({

          success: false,

          message:
            "Ride cannot be started now."

        });
      }


      /*
       * =====================================================
       * 🔐 PASSENGER START CODE
       * =====================================================
       *
       * Driver dashboard se:
       *
       * req.body.startCode
       *
       * aayega.
       */

      const enteredCode =
        String(
          req.body.startCode ||
            ""
        ).trim();


      /*
       * CODE REQUIRED
       */

      if (!enteredCode) {

        return res.status(400).json({

          success: false,

          message:
            "Passenger start code is required."

        });
      }


      /*
       * CODE ALREADY USED
       */

      if (
        ride.startCodeVerified ===
        true
      ) {

        return res.status(409).json({

          success: false,

          message:
            "Ride start code has already been used."

        });
      }


      /*
       * STORED CODE CHECK
       */

      if (!ride.startCode) {

        return res.status(400).json({

          success: false,

          message:
            "Start code is not available for this ride."

        });
      }


      /*
       * =====================================================
       * 🔐 VERIFY CODE
       * =====================================================
       */

      if (
        enteredCode !==
        String(
          ride.startCode
        )
      ) {

        /*
         * ❌ WRONG CODE
         *
         * Ride start nahi hogi.
         */

        return res.status(400).json({

          success: false,

          message:
            "❌ Wrong passenger start code."

        });
      }


      /*
       * =====================================================
       * ✅ CODE CORRECT
       * =====================================================
       */

      ride.startCodeVerified =
        true;

      ride.startCodeVerifiedAt =
        new Date();


      /*
       * RIDE START
       */

      ride.status =
        "Ride started";

      ride.startedAt =
        new Date();


      /*
       * 🔐 IMPORTANT
       *
       * Code successful verification ke
       * baad database se remove kar do.
       *
       * Isse same code dobara use nahi ho sakta.
       */

      ride.startCode =
        null;


      await ride.save();


      return res.json({

        success: true,

        message:
          "✅ Start code verified. Ride started successfully.",

        ride:
          safeRide(ride)

      });

    } catch (error) {

      console.error(
        "START RIDE ERROR:",
        error
      );

      return res.status(500).json({

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


      if (
        !ride.driverId ||
        String(
          ride.driverId
        ) !==
          String(
            req.user._id
          )
      ) {

        return res.status(403).json({

          success: false,

          message:
            "You are not assigned to this ride."

        });
      }


      /*
       * Driver accepted OR Ride started
       */

      if (
        ![
          "Driver accepted",
          "Ride started"
        ].includes(
          ride.status
        )
      ) {

        return res.status(409).json({

          success: false,

          message:
            "Ride cannot be completed now."

        });
      }


      ride.status =
        "Completed";

      ride.completedAt =
        new Date();

      await ride.save();


      return res.json({

        success: true,

        message:
          "Ride completed successfully.",

        ride:
          safeRide(ride)

      });

    } catch (error) {

      console.error(
        "COMPLETE RIDE ERROR:",
        error
      );

      return res.status(500).json({

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


      const isPassenger =
        String(
          ride.userId
        ) ===
        String(
          req.user._id
        );


      const isDriver =
        ride.driverId &&
        String(
          ride.driverId
        ) ===
        String(
          req.user._id
        );


      if (
        !isPassenger &&
        !isDriver
      ) {

        return res.status(403).json({

          success: false,

          message:
            "You cannot cancel this ride."

        });
      }


      if (
        [
          "Completed",
          "Cancelled"
        ].includes(
          ride.status
        )
      ) {

        return res.status(409).json({

          success: false,

          message:
            "Ride is already finished."

        });
      }


      ride.status =
        "Cancelled";

      ride.cancelledAt =
        new Date();

      ride.cancelledBy =
        req.user.role;

      ride.cancelReason =
        req.body.reason ||
        "Cancelled by user";


      await ride.save();


      return res.json({

        success: true,

        message:
          "Ride cancelled successfully.",

        ride:
          safeRide(ride)

      });

    } catch (error) {

      console.error(
        "CANCEL RIDE ERROR:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "Unable to cancel ride."

      });
    }
  }
);
/* =========================================================
   DRIVER PROFILE
========================================================= */

app.get(
  "/api/driver/profile",
  authenticate,
  requireRole("driver"),
  async (req, res) => {

    try {

      const driver =
        await User.findById(
          req.user._id
        ).select(
          "-password"
        );

      return res.json({

        success: true,

        driver:
          safeUser(
            driver
          )

      });

    } catch (error) {

      return res.status(500).json({

        success: false,

        message:
          "Unable to load driver profile."

      });
    }
  }
);


/* =========================================================
   PASSENGER PROFILE
========================================================= */

app.get(
  "/api/passenger/profile",
  authenticate,
  requireRole("passenger"),
  async (req, res) => {

    try {

      const passenger =
        await User.findById(
          req.user._id
        ).select(
          "-password"
        );

      return res.json({

        success: true,

        passenger:
          safeUser(
            passenger
          )

      });

    } catch (error) {

      return res.status(500).json({

        success: false,

        message:
          "Unable to load passenger profile."

      });
    }
  }
);


/* =========================================================
   UPDATE PROFILE
========================================================= */

app.patch(
  "/api/profile",
  authenticate,

  async (req, res) => {

    try {

      const {
        name,
        city,
        vehicleNumber,
        vehicleType,
        license
      } = req.body;


      if (
        name !== undefined
      ) {

        req.user.name =
          String(
            name
          ).trim();

      }


      if (
        city !== undefined
      ) {

        req.user.city =
          String(
            city
          ).trim();

      }


      if (
        req.user.role ===
        "driver"
      ) {

        if (
          vehicleNumber !==
          undefined
        ) {

          req.user.vehicleNumber =
            String(
              vehicleNumber
            )
              .trim()
              .toUpperCase();

        }


        if (
          vehicleType !==
          undefined
        ) {

          req.user.vehicleType =
            String(
              vehicleType
            ).trim();

        }


        if (
          license !==
          undefined
        ) {

          req.user.license =
            String(
              license
            )
              .trim()
              .toUpperCase();

        }
      }


      await req.user.save();


      return res.json({

        success: true,

        message:
          "Profile updated successfully.",

        user:
          safeUser(
            req.user
          )

      });

    } catch (error) {

      console.error(
        "PROFILE UPDATE ERROR:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "Unable to update profile."

      });
    }
  }
);


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  "/api/health",

  (req, res) => {

    res.json({

      success: true,

      status:
        "OK",

      service:
        "UDAN CAB",

      time:
        new Date().toISOString()

    });

  }
);


/* =========================================================
   FRONTEND STATIC FILES
========================================================= */

app.use(
  express.static(
    FRONTEND_DIR
  )
);


/* =========================================================
   FRONTEND ROUTES
========================================================= */

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
  "/login",

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
  "/dashboard",

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
  "/driver-dashboard",

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
  "/admin",

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
  "/parcel",

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
   404 API
========================================================= */

app.use(
  "/api",

  (req, res) => {

    res.status(404).json({

      success: false,

      message:
        "API endpoint not found."

    });

  }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      "SERVER ERROR:",
      error
    );

    res.status(
      error.status || 500
    ).json({

      success: false,

      message:
        error.message ||
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
          `🚕 UDAN CAB server running on port ${PORT}`
        );

      }
    );


  } catch (error) {

    console.error(
      "❌ MongoDB connection failed:",
      error
    );

    process.exit(1);

  }
}


startServer();