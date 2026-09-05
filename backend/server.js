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

const PORT = process.env.PORT || 5000;

const MONGODB_URI = process.env.MONGODB_URI;

const JWT_SECRET = process.env.JWT_SECRET;


/* =====================================================
   BASIC CHECK
===================================================== */

if (!MONGODB_URI) {
    console.error("❌ MONGODB_URI is missing.");
    process.exit(1);
}

if (!JWT_SECRET) {
    console.error("❌ JWT_SECRET is missing.");
    process.exit(1);
}


/* =====================================================
   MIDDLEWARE
===================================================== */

app.use(
    cors({
        origin: true,
        credentials: true
    })
);

app.use(
    express.json()
);


/* =====================================================
   FRONTEND FILES
===================================================== */

/*
   IMPORTANT:

   All frontend HTML files are inside:

   backend/

   So we serve files from __dirname.
*/

app.use(
    express.static(__dirname)
);


/* =====================================================
   MONGODB CONNECTION
===================================================== */

mongoose
    .connect(MONGODB_URI)
    .then(() => {

        console.log(
            "========================================"
        );

        console.log(
            "✅ MongoDB Connected Successfully"
        );

        console.log(
            "🗄️ Database: udan"
        );

        console.log(
            "========================================"
        );

    })
    .catch((error) => {

        console.error(
            "❌ MongoDB Connection Failed"
        );

        console.error(
            error.message
        );

    });


/* =====================================================
   CREATE JWT TOKEN
===================================================== */

function createToken(user) {

    return jwt.sign(

        {
            id:
                user._id.toString(),

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


/* =====================================================
   ROLE NORMALIZATION
===================================================== */

function normalizeRole(role) {

    if (
        role === "user"
    ) {

        return "passenger";

    }

    return role;

}


function frontendRole(role) {

    if (
        role === "passenger"
    ) {

        return "user";

    }

    return role;

}


/* =====================================================
   SAFE USER
===================================================== */

function safeUser(user) {

    return {

        id:
            user._id,

        name:
            user.name,

        email:
            user.email,

        role:
            frontendRole(
                user.role
            ),

        city:
            user.city,

        vehicleNumber:
            user.vehicleNumber,

        vehicleType:
            user.vehicleType,

        license:
            user.license,

        rating:
            user.rating,

        online:
            user.online,

        blocked:
            user.blocked === true,

        location:
            user.location

    };

}


/* =====================================================
   AUTHENTICATION MIDDLEWARE
===================================================== */

async function authenticate(
    req,
    res,
    next
) {

    try {

        const authHeader =
            req.headers.authorization;


        if (
            !authHeader ||
            !authHeader.startsWith(
                "Bearer "
            )
        ) {

            return res.status(401).json({

                success:
                    false,

                message:
                    "Authentication token required."

            });

        }


        const token =
            authHeader.split(
                " "
            )[1];


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

            return res.status(401).json({

                success:
                    false,

                message:
                    "User account not found."

            });

        }


        /*
           BLOCKED DRIVER CHECK
        */

        if (
            user.role === "driver" &&
            user.blocked === true
        ) {

            return res.status(403).json({

                success:
                    false,

                blocked:
                    true,

                message:
                    "🚫 Your driver account has been blocked by UDAN Admin."

            });

        }


        req.user =
            user;


        next();

    }

    catch (error) {

        return res.status(401).json({

            success:
                false,

            message:
                "Invalid or expired authentication token."

        });

    }

}


/* =====================================================
   ROLE MIDDLEWARE
===================================================== */

function requireRole(
    ...roles
) {

    return function (
        req,
        res,
        next
    ) {

        if (
            !req.user ||
            !roles.includes(
                req.user.role
            )
        ) {

            return res.status(403).json({

                success:
                    false,

                message:
                    "You are not authorized for this action."

            });

        }


        next();

    };

}


/* =====================================================
   DISTANCE CALCULATION
===================================================== */

function distanceKm(
    lat1,
    lng1,
    lat2,
    lng2
) {

    const R = 6371;


    const dLat =
        (
            Number(lat2) -
            Number(lat1)
        ) *
        Math.PI /
        180;


    const dLng =
        (
            Number(lng2) -
            Number(lng1)
        ) *
        Math.PI /
        180;


    const a =
        Math.sin(
            dLat / 2
        ) *
        Math.sin(
            dLat / 2
        ) +

        Math.cos(
            Number(lat1) *
            Math.PI /
            180
        ) *

        Math.cos(
            Number(lat2) *
            Math.PI /
            180
        ) *

        Math.sin(
            dLng / 2
        ) *
        Math.sin(
            dLng / 2
        );


    const c =
        2 *
        Math.atan2(
            Math.sqrt(a),
            Math.sqrt(1 - a)
        );


    return R * c;

}


/* =====================================================
   HOME
===================================================== */

app.get(
    "/",
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "index.html"
            )
        );

    }
);


/* =====================================================
   REGISTER
===================================================== */

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

                    success:
                        false,

                    message:
                        "Email, password and role are required."

                });

            }


            const normalizedRole =
                normalizeRole(
                    role
                );


            if (
                ![
                    "passenger",
                    "driver",
                    "admin"
                ].includes(
                    normalizedRole
                )
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Invalid role."

                });

            }


            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();


            const existingUser =
                await User.findOne({

                    email:
                        cleanEmail

                });


            if (existingUser) {

                return res.status(409).json({

                    success:
                        false,

                    message:
                        "This email is already registered."

                });

            }


            const hashedPassword =
                await bcrypt.hash(
                    password,
                    12
                );


            const newUser =
                await User.create({

                    name:
                        name ||
                        "UDAN User",

                    email:
                        cleanEmail,

                    password:
                        hashedPassword,

                    role:
                        normalizedRole,

                    city:
                        city ||
                        "Nalanda",

                    vehicleNumber:
                        vehicleNumber ||
                        "",

                    vehicleType:
                        vehicleType ||
                        "",

                    license:
                        license ||
                        "",

                    rating:
                        4.8,

                    online:
                        false,

                    blocked:
                        false,

                    blockedReason:
                        "",

                    blockedAt:
                        null

                });


            console.log(
                "✅ New user:",
                newUser.email,
                newUser.role
            );


            res.status(201).json({

                success:
                    true,

                message:
                    "Registration successful!",

                user:
                    safeUser(
                        newUser
                    )

            });

        }

        catch (error) {

            console.error(
                "REGISTER ERROR:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Registration failed.",

                error:
                    error.message

            });

        }

    }
);


/* =====================================================
   LOGIN
===================================================== */

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

                    success:
                        false,

                    message:
                        "Email, password and role are required."

                });

            }


            const normalizedRole =
                normalizeRole(
                    role
                );


            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();


            const user =
                await User.findOne({

                    email:
                        cleanEmail,

                    role:
                        normalizedRole

                });


            if (!user) {

                return res.status(401).json({

                    success:
                        false,

                    message:
                        "Invalid email, password or role."

                });

            }


            if (
                user.blocked === true &&
                user.role === "driver"
            ) {

                return res.status(403).json({

                    success:
                        false,

                    blocked:
                        true,

                    message:
                        "🚫 Your driver account has been blocked by UDAN Admin."

                });

            }


            const passwordMatch =
                await bcrypt.compare(
                    password,
                    user.password
                );


            if (!passwordMatch) {

                return res.status(401).json({

                    success:
                        false,

                    message:
                        "Invalid email, password or role."

                });

            }


            const token =
                createToken(
                    user
                );


            res.json({

                success:
                    true,

                message:
                    "Login successful!",

                token:
                    token,

                user:
                    safeUser(
                        user
                    )

            });

        }

        catch (error) {

            console.error(
                "LOGIN ERROR:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Login failed.",

                error:
                    error.message

            });

        }

    }
);


/* =====================================================
   CURRENT USER
===================================================== */

app.get(
    "/api/me",
    authenticate,
    async (req, res) => {

        res.json({

            success:
                true,

            user:
                safeUser(
                    req.user
                )

        });

    }
);


/* =====================================================
   DRIVER ONLINE / OFFLINE
===================================================== */

app.post(
    "/api/driver/status",
    authenticate,
    requireRole("driver"),
    async (req, res) => {

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

                success:
                    true,

                message:
                    online
                        ? "Driver is online."
                        : "Driver is offline.",

                online:
                    req.user.online

            });

        }

        catch (error) {

            console.error(
                "DRIVER STATUS ERROR:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to update driver status."

            });

        }

    }
);


/* =====================================================
   UPDATE LOCATION
===================================================== */

app.post(
    "/api/location/update",
    authenticate,
    async (req, res) => {

        try {

            const {

                latitude,

                longitude,

                accuracy

            } = req.body;


            const lat =
                Number(
                    latitude
                );


            const lng =
                Number(
                    longitude
                );


            if (
                !Number.isFinite(lat) ||
                !Number.isFinite(lng)
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Invalid latitude or longitude."

                });

            }


            req.user.location = {

                lat:
                    lat,

                lng:
                    lng,

                accuracy:
                    Number.isFinite(
                        Number(
                            accuracy
                        )
                    )
                        ? Number(
                            accuracy
                        )
                        : null,

                updatedAt:
                    new Date()

            };


            if (
                req.user.role === "driver"
            ) {

                req.user.online =
                    true;

            }


            await req.user.save();


            res.json({

                success:
                    true,

                message:
                    "Location updated.",

                location:
                    req.user.location

            });

        }

        catch (error) {

            console.error(
                "LOCATION ERROR:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to update location."

            });

        }

    }
);


/* =====================================================
   NEARBY DRIVERS
===================================================== */

app.get(
    "/api/drivers/nearby",
    authenticate,
    requireRole("passenger"),
    async (req, res) => {

        try {

            const lat =
                Number(
                    req.query.lat ??
                    req.query.latitude
                );


            const lng =
                Number(
                    req.query.lng ??
                    req.query.longitude
                );


            const vehicleType =
                String(
                    req.query.vehicleType ||
                    ""
                ).trim();


            const serviceArea =
                String(
                    req.query.serviceArea ||
                    req.user.city ||
                    "Nalanda"
                ).trim();


            if (
                !Number.isFinite(lat) ||
                !Number.isFinite(lng)
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Valid latitude and longitude are required.",

                    drivers:
                        []

                });

            }


            let drivers =
                await User.find({

                    role:
                        "driver",

                    online:
                        true,

                    blocked:
                        {
                            $ne:
                                true
                        },

                    city:
                        serviceArea

                })
                .select(
                    "name email vehicleType vehicleNumber rating location city online"
                )
                .lean();


            if (vehicleType) {

                drivers =
                    drivers.filter(
                        driver =>
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
                    .map(
                        driver => {

                            const d =
                                distanceKm(

                                    lat,

                                    lng,

                                    driver.location.lat,

                                    driver.location.lng

                                );


                            return {

                                ...driver,

                                distanceKm:
                                    Number(
                                        d.toFixed(2)
                                    )

                            };

                        }
                    )
                    .sort(
                        (
                            a,
                            b
                        ) =>
                            a.distanceKm -
                            b.distanceKm
                    );


            res.json({

                success:
                    true,

                drivers:
                    drivers

            });

        }

        catch (error) {

            console.error(
                "NEARBY ERROR:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to find nearby drivers.",

                drivers:
                    []

            });

        }

    }
);


/* =====================================================
   BOOK RIDE
===================================================== */

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

                destinationLongitude,

                passengerLatitude,

                passengerLongitude

            } = req.body;


            const finalPickupLat =
                pickupLatitude !== undefined
                    ? Number(
                        pickupLatitude
                    )
                    : Number(
                        passengerLatitude
                    );


            const finalPickupLng =
                pickupLongitude !== undefined
                    ? Number(
                        pickupLongitude
                    )
                    : Number(
                        passengerLongitude
                    );


            if (
                !pickup ||
                !destination ||
                !cabType ||
                fare === undefined
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Pickup, destination, cab type and fare are required."

                });

            }


            const ride =
                await Ride.create({

                    userId:
                        req.user._id,

                    pickup:
                        pickup,

                    destination:
                        destination,

                    cabType:
                        cabType,

                    fare:
                        Number(
                            fare
                        ),

                    vehicleType:
                        vehicleType ||
                        null,

                    parcelType:
                        parcelType ||
                        null,

                    parcelWeight:
                        parcelWeight !== undefined
                            ? String(
                                parcelWeight
                            )
                            : null,

                    serviceArea:
                        serviceArea ||
                        req.user.city ||
                        "Nalanda",

                    status:
                        "Searching for driver",

                    passengerLocation: {

                        lat:
                            Number.isFinite(
                                finalPickupLat
                            )
                                ? finalPickupLat
                                : null,

                        lng:
                            Number.isFinite(
                                finalPickupLng
                            )
                                ? finalPickupLng
                                : null,

                        accuracy:
                            null,

                        updatedAt:
                            new Date()

                    },

                    destinationLocation: {

                        lat:
                            Number.isFinite(
                                Number(
                                    destinationLatitude
                                )
                            )
                                ? Number(
                                    destinationLatitude
                                )
                                : null,

                        lng:
                            Number.isFinite(
                                Number(
                                    destinationLongitude
                                )
                            )
                                ? Number(
                                    destinationLongitude
                                )
                                : null

                    }

                });


            /*
               AUTO ASSIGN NEAREST DRIVER
            */

            if (
                Number.isFinite(
                    finalPickupLat
                ) &&
                Number.isFinite(
                    finalPickupLng
                )
            ) {

                let drivers =
                    await User.find({

                        role:
                            "driver",

                        online:
                            true,

                        blocked:
                            {
                                $ne:
                                    true
                            },

                        city:
                            ride.serviceArea

                    }).lean();


                if (
                    ride.vehicleType
                ) {

                    drivers =
                        drivers.filter(
                            driver =>
                                driver.vehicleType ===
                                ride.vehicleType
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
                        .map(
                            driver => {

                                return {

                                    driver:
                                        driver,

                                    distanceKm:
                                        distanceKm(

                                            finalPickupLat,

                                            finalPickupLng,

                                            driver.location.lat,

                                            driver.location.lng

                                        )

                                };

                            }
                        )
                        .sort(
                            (
                                a,
                                b
                            ) =>
                                a.distanceKm -
                                b.distanceKm
                        );


                if (
                    drivers.length > 0
                ) {

                    ride.assignedDriverId =
                        drivers[0]
                            .driver
                            ._id;


                    ride.assignedDistanceKm =
                        Number(
                            drivers[0]
                                .distanceKm
                                .toFixed(2)
                        );


                    await ride.save();

                }

            }


            res.status(201).json({

                success:
                    true,

                message:
                    "Ride booked successfully!",

                ride:
                    ride

            });

        }

        catch (error) {

            console.error(
                "BOOK RIDE ERROR:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to book ride.",

                error:
                    error.message

            });

        }

    }
);


/* =====================================================
   DRIVER AVAILABLE RIDES
===================================================== */

app.get(
    "/api/driver/rides",
    authenticate,
    requireRole("driver"),
    async (req, res) => {

        try {

            const rides =
                await Ride.find({

                    status:
                        "Searching for driver",

                    driverId:
                        null,

                    $or: [

                        {
                            assignedDriverId:
                                req.user._id
                        },

                        {
                            assignedDriverId:
                                null
                        },

                        {
                            assignedDriverId:
                                {
                                    $exists:
                                        false
                                }
                        }

                    ]

                })
                .populate(
                    "userId",
                    "name email city"
                )
                .sort({
                    createdAt:
                        -1
                });


            res.json({

                success:
                    true,

                rides:
                    rides

            });

        }

        catch (error) {

            console.error(
                "DRIVER RIDES ERROR:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to load available rides.",

                rides:
                    []

            });

        }

    }
);


/* =====================================================
   ACCEPT RIDE
===================================================== */

app.post(
    "/api/rides/:id/accept",
    authenticate,
    requireRole("driver"),
    async (req, res) => {

        try {

            if (
                req.user.blocked === true
            ) {

                return res.status(403).json({

                    success:
                        false,

                    blocked:
                        true,

                    message:
                        "🚫 Driver account is blocked."

                });

            }


            const ride =
                await Ride.findById(
                    req.params.id
                );


            if (!ride) {

                return res.status(404).json({

                    success:
                        false,

                    message:
                        "Ride not found."

                });

            }


            if (
                ride.assignedDriverId &&
                ride.assignedDriverId.toString() !==
                    req.user._id.toString()
            ) {

                return res.status(403).json({

                    success:
                        false,

                    message:
                        "This ride is assigned to another driver."

                });

            }


            if (
                ride.driverId
            ) {

                return res.status(409).json({

                    success:
                        false,

                    message:
                        "Ride already accepted."

                });

            }


            if (
                ride.status !==
                "Searching for driver"
            ) {

                return res.status(409).json({

                    success:
                        false,

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
                "Driver assigned";


            if (
                req.user.location &&
                req.user.location.lat !== null &&
                req.user.location.lng !== null
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

                success:
                    true,

                message:
                    "🚕 Ride accepted successfully!",

                ride:
                    ride

            });

        }

        catch (error) {

            console.error(
                "ACCEPT RIDE ERROR:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to accept ride."

            });

        }

    }
);


/* =====================================================
   PASSENGER MY RIDES
===================================================== */

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
                    createdAt:
                        -1
                });


            res.json({

                success:
                    true,

                rides:
                    rides

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to load your rides.",

                rides:
                    []

            });

        }

    }
);


/* =====================================================
   DRIVER MY RIDES
===================================================== */

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
                    createdAt:
                        -1
                });


            res.json({

                success:
                    true,

                rides:
                    rides

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to load driver rides.",

                rides:
                    []

            });

        }

    }
);


/* =====================================================
   SINGLE RIDE
===================================================== */

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
                    "name email vehicleNumber vehicleType rating location online blocked"
                );


            if (!ride) {

                return res.status(404).json({

                    success:
                        false,

                    message:
                        "Ride not found."

                });

            }


            const passengerAllowed =
                ride.userId &&
                ride.userId._id.toString() ===
                    req.user._id.toString();


            const driverAllowed =
                ride.driverId &&
                ride.driverId._id.toString() ===
                    req.user._id.toString();


            const adminAllowed =
                req.user.role ===
                "admin";


            if (
                !passengerAllowed &&
                !driverAllowed &&
                !adminAllowed
            ) {

                return res.status(403).json({

                    success:
                        false,

                    message:
                        "You are not allowed to view this ride."

                });

            }


            res.json({

                success:
                    true,

                ride:
                    ride

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to load ride."

            });

        }

    }
);


/* =====================================================
   START RIDE
===================================================== */

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

                    success:
                        false,

                    message:
                        "Ride not found."

                });

            }


            ride.status =
                "Ride started";


            await ride.save();


            res.json({

                success:
                    true,

                message:
                    "🚕 Ride started.",

                ride:
                    ride

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to start ride."

            });

        }

    }
);


/* =====================================================
   COMPLETE RIDE
===================================================== */

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

                    success:
                        false,

                    message:
                        "Ride not found."

                });

            }


            ride.status =
                "Completed";


            await ride.save();


            res.json({

                success:
                    true,

                message:
                    "✅ Ride completed successfully.",

                ride:
                    ride

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to complete ride."

            });

        }

    }
);


/* =====================================================
   CANCEL RIDE
===================================================== */

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

                    success:
                        false,

                    message:
                        "Ride not found."

                });

            }


            const passengerAllowed =
                ride.userId &&
                ride.userId.toString() ===
                    req.user._id.toString();


            const driverAllowed =
                ride.driverId &&
                ride.driverId.toString() ===
                    req.user._id.toString();


            const adminAllowed =
                req.user.role ===
                "admin";


            if (
                !passengerAllowed &&
                !driverAllowed &&
                !adminAllowed
            ) {

                return res.status(403).json({

                    success:
                        false,

                    message:
                        "You are not allowed to cancel this ride."

                });

            }


            ride.status =
                "Cancelled";


            await ride.save();


            res.json({

                success:
                    true,

                message:
                    "Ride cancelled.",

                ride:
                    ride

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to cancel ride."

            });

        }

    }
);


/* =====================================================
   PASSENGER LOCATION FOR RIDE
===================================================== */

app.patch(
    "/api/rides/:id/passenger-location",
    authenticate,
    requireRole("passenger"),
    async (req, res) => {

        try {

            const {

                latitude,

                longitude,

                accuracy

            } = req.body;


            const ride =
                await Ride.findOne({

                    _id:
                        req.params.id,

                    userId:
                        req.user._id

                });


            if (!ride) {

                return res.status(404).json({

                    success:
                        false,

                    message:
                        "Ride not found."

                });

            }


            ride.passengerLocation = {

                lat:
                    Number(
                        latitude
                    ),

                lng:
                    Number(
                        longitude
                    ),

                accuracy:
                    Number(
                        accuracy
                    ) || null,

                updatedAt:
                    new Date()

            };


            await ride.save();


            res.json({

                success:
                    true,

                message:
                    "Passenger location updated.",

                location:
                    ride.passengerLocation

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to update passenger location."

            });

        }

    }
);


/* =====================================================
   DRIVER LOCATION FOR RIDE
===================================================== */

app.patch(
    "/api/rides/:id/driver-location",
    authenticate,
    requireRole("driver"),
    async (req, res) => {

        try {

            const {

                latitude,

                longitude,

                accuracy

            } = req.body;


            const ride =
                await Ride.findOne({

                    _id:
                        req.params.id,

                    driverId:
                        req.user._id

                });


            if (!ride) {

                return res.status(404).json({

                    success:
                        false,

                    message:
                        "Ride not found."

                });

            }


            ride.driverLocation = {

                lat:
                    Number(
                        latitude
                    ),

                lng:
                    Number(
                        longitude
                    ),

                accuracy:
                    Number(
                        accuracy
                    ) || null,

                updatedAt:
                    new Date()

            };


            await ride.save();


            res.json({

                success:
                    true,

                message:
                    "Driver location updated.",

                location:
                    ride.driverLocation

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to update driver location."

            });

        }

    }
);


/* =====================================================
   ADMIN PASSENGERS
===================================================== */

app.get(
    "/api/admin/passengers",
    authenticate,
    requireRole("admin"),
    async (req, res) => {

        try {

            const passengers =
                await User.find({

                    role:
                        "passenger"

                })
                .select(
                    "name email city rating location createdAt"
                )
                .sort({
                    createdAt:
                        -1
                })
                .lean();


            res.json({

                success:
                    true,

                passengers:
                    passengers

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to load passengers.",

                passengers:
                    []

            });

        }

    }
);


/* =====================================================
   ADMIN DRIVERS
===================================================== */

app.get(
    "/api/admin/drivers",
    authenticate,
    requireRole("admin"),
    async (req, res) => {

        try {

            const drivers =
                await User.find({

                    role:
                        "driver"

                })
                .select(
                    "-password"
                )
                .sort({
                    createdAt:
                        -1
                })
                .lean();


            res.json({

                success:
                    true,

                drivers:
                    drivers

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to load drivers.",

                drivers:
                    []

            });

        }

    }
);


/* =====================================================
   ADMIN BLOCK DRIVER
===================================================== */

app.patch(
    "/api/admin/drivers/:id/block",
    authenticate,
    requireRole("admin"),
    async (req, res) => {

        try {

            const reason =
                req.body?.reason ||
                "Blocked by UDAN Admin";


            const driver =
                await User.findOneAndUpdate(

                    {
                        _id:
                            req.params.id,

                        role:
                            "driver"

                    },

                    {
                        $set: {

                            blocked:
                                true,

                            blockedReason:
                                reason,

                            blockedAt:
                                new Date(),

                            online:
                                false

                        }

                    },

                    {
                        new:
                            true
                    }

                )
                .select(
                    "-password"
                )
                .lean();


            if (!driver) {

                return res.status(404).json({

                    success:
                        false,

                    message:
                        "Driver not found."

                });

            }


            res.json({

                success:
                    true,

                message:
                    "🚫 Driver blocked successfully.",

                driver:
                    driver

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to block driver."

            });

        }

    }
);


/* =====================================================
   ADMIN UNBLOCK DRIVER
===================================================== */

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

                        role:
                            "driver"

                    },

                    {
                        $set: {

                            blocked:
                                false,

                            blockedReason:
                                "",

                            blockedAt:
                                null

                        }

                    },

                    {
                        new:
                            true
                    }

                )
                .select(
                    "-password"
                )
                .lean();


            if (!driver) {

                return res.status(404).json({

                    success:
                        false,

                    message:
                        "Driver not found."

                });

            }


            res.json({

                success:
                    true,

                message:
                    "✅ Driver unblocked successfully.",

                driver:
                    driver

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to unblock driver."

            });

        }

    }
);


/* =====================================================
   ADMIN REMOVE DRIVER
===================================================== */

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

                    role:
                        "driver"

                });


            if (!driver) {

                return res.status(404).json({

                    success:
                        false,

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

                    success:
                        false,

                    message:
                        "Driver has an active ride."

                });

            }


            await User.deleteOne({

                _id:
                    driver._id

            });


            res.json({

                success:
                    true,

                message:
                    "🗑️ Driver removed successfully."

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to remove driver."

            });

        }

    }
);


/* =====================================================
   ADMIN ALL RIDES
===================================================== */

app.get(
    "/api/admin/rides",
    authenticate,
    requireRole("admin"),
    async (req, res) => {

        try {

            const rides =
                await Ride.find({})
                .populate(
                    "userId",
                    "name email city"
                )
                .populate(
                    "driverId",
                    "name email vehicleNumber vehicleType rating online blocked"
                )
                .sort({
                    createdAt:
                        -1
                });


            res.json({

                success:
                    true,

                rides:
                    rides

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to load rides.",

                rides:
                    []

            });

        }

    }
);


/* =====================================================
   ADMIN STATS
===================================================== */

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

                    User.countDocuments({}),

                    User.countDocuments({

                        role:
                            "driver"

                    }),

                    User.countDocuments({

                        role:
                            "driver",

                        blocked:
                            true

                    }),

                    Ride.countDocuments({}),

                    Ride.countDocuments({

                        status:
                            "Completed"

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

                success:
                    true,

                stats: {

                    totalUsers,

                    totalDrivers,

                    blockedDrivers,

                    totalRides,

                    completedRides,

                    activeRides

                }

            });

        }

        catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to load admin stats."

            });

        }

    }
);


/* =====================================================
   FRONTEND PAGE ALIASES
===================================================== */

/*
   GitHub screenshot me filenames:

   dashboard(1).html
   driver-dashboard(1).html
   admin(1).html
   parcel(1).html

   Lekin frontend normally:

   dashboard.html
   driver-dashboard.html
   admin.html
   parcel.html

   request karta hai.

   Isliye yaha aliases diye gaye hain.
*/


/* ================= LOGIN ================= */

app.get(
    "/login.html",
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "login.html"
            )
        );

    }
);


/* ================= DASHBOARD ================= */

app.get(
    "/dashboard.html",
    (req, res) => {

        const normalFile =
            path.join(
                __dirname,
                "dashboard.html"
            );


        res.sendFile(
            normalFile,
            (error) => {

                if (error) {

                    res.sendFile(
                        path.join(
                            __dirname,
                            "dashboard(1).html"
                        )
                    );

                }

            }
        );

    }
);


/* ================= DRIVER DASHBOARD ================= */

app.get(
    "/driver-dashboard.html",
    (req, res) => {

        const normalFile =
            path.join(
                __dirname,
                "driver-dashboard.html"
            );


        res.sendFile(
            normalFile,
            (error) => {

                if (error) {

                    res.sendFile(
                        path.join(
                            __dirname,
                            "driver-dashboard(1).html"
                        )
                    );

                }

            }
        );

    }
);


/* ================= ADMIN ================= */

app.get(
    "/admin.html",
    (req, res) => {

        const normalFile =
            path.join(
                __dirname,
                "admin.html"
            );


        res.sendFile(
            normalFile,
            (error) => {

                if (error) {

                    res.sendFile(
                        path.join(
                            __dirname,
                            "admin(1).html"
                        )
                    );

                }

            }
        );

    }
);


/* ================= PARCEL ================= */

app.get(
    "/parcel.html",
    (req, res) => {

        const normalFile =
            path.join(
                __dirname,
                "parcel.html"
            );


        res.sendFile(
            normalFile,
            (error) => {

                if (error) {

                    res.sendFile(
                        path.join(
                            __dirname,
                            "parcel(1).html"
                        )
                    );

                }

            }
        );

    }
);


/* =====================================================
   404
===================================================== */

app.use(
    (req, res) => {

        res.status(404).json({

            success:
                false,

            message:
                "API route not found.",

            path:
                req.originalUrl

        });

    }
);


/* =====================================================
   GLOBAL ERROR HANDLER
===================================================== */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "GLOBAL ERROR:",
            error
        );


        res.status(500).json({

            success:
                false,

            message:
                "Internal server error.",

            error:
                error.message

        });

    }
);


/* =====================================================
   START SERVER
===================================================== */

app.listen(
    PORT,
    () => {

        console.log(
            "========================================"
        );

        console.log(
            `🚕 UDAN Server running on port ${PORT}`
        );

        console.log(
            "✅ MongoDB enabled"
        );

        console.log(
            "✅ Login/Register enabled"
        );

        console.log(
            "✅ Passenger system enabled"
        );

        console.log(
            "✅ Driver system enabled"
        );

        console.log(
            "✅ Admin system enabled"
        );

        console.log(
            "✅ GPS system enabled"
        );

        console.log(
            "✅ Ride booking enabled"
        );

        console.log(
            "✅ Parcel system enabled"
        );

        console.log(
            "✅ Frontend pages enabled"
        );

        console.log(
            "========================================"
        );

    }
);
