require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");

const User = require("../model/user");
const Ride = require("../model/ride");

const app = express();

const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

const FRONTEND_DIR = path.join(__dirname, "..");

/* =====================================================
   ENV CHECK
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

app.use(express.json({ limit: "2mb" }));

/* =====================================================
   FRONTEND STATIC FILES
===================================================== */

app.use(express.static(FRONTEND_DIR));

/* =====================================================
   MONGODB
===================================================== */

mongoose
    .connect(MONGODB_URI)
    .then(() => {
        console.log("✅ MongoDB connected");
    })
    .catch((error) => {
        console.error(
            "❌ MongoDB connection error:",
            error.message
        );
    });

/* =====================================================
   HELPERS
===================================================== */

function normalizeRole(role) {
    if (role === "user") return "passenger";
    return role;
}

function frontendRole(role) {
    if (role === "passenger") return "user";
    return role;
}

function createToken(user) {
    return jwt.sign(
        {
            id: user._id.toString(),
            email: user.email,
            role: user.role
        },
        JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
}

function safeUser(user) {
    return {
        id: user._id,
        _id: user._id,
        name: user.name,
        email: user.email,
        role: frontendRole(user.role),
        city: user.city,
        vehicleType: user.vehicleType,
        vehicleNumber: user.vehicleNumber,
        license: user.license,
        rating: user.rating,
        online: user.online,
        blocked: user.blocked === true,
        blockedReason: user.blockedReason || "",
        blockedAt: user.blockedAt || null,
        location: user.location || null
    };
}

function sendPage(res, possibleFiles, errorMessage) {
    for (const fileName of possibleFiles) {
        const fullPath = path.join(
            FRONTEND_DIR,
            fileName
        );

        if (fs.existsSync(fullPath)) {
            return res.sendFile(fullPath);
        }
    }

    return res
        .status(404)
        .send(errorMessage);
}

function distanceKm(lat1, lng1, lat2, lng2) {
    const R = 6371;
    const dLat =
        ((lat2 - lat1) * Math.PI) / 180;
    const dLng =
        ((lng2 - lng1) * Math.PI) / 180;

    const a =
        Math.sin(dLat / 2) ** 2 +
        Math.cos(
            (lat1 * Math.PI) / 180
        ) *
            Math.cos(
                (lat2 * Math.PI) / 180
            ) *
            Math.sin(dLng / 2) ** 2;

    return (
        2 *
        R *
        Math.atan2(
            Math.sqrt(a),
            Math.sqrt(1 - a)
        )
    );
}

function toNumber(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
}

function isObjectId(value) {
    return mongoose.Types.ObjectId.isValid(value);
}

/* =====================================================
   AUTHENTICATION
===================================================== */

async function authenticate(req, res, next) {
    try {
        const header =
            req.headers.authorization;

        if (
            !header ||
            !header.startsWith("Bearer ")
        ) {
            return res.status(401).json({
                success: false,
                message:
                    "Authentication token required."
            });
        }

        const token =
            header.substring(7).trim();

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
                success: false,
                message:
                    "User account not found."
            });
        }

        if (
            user.role === "driver" &&
            user.blocked === true
        ) {
            return res.status(403).json({
                success: false,
                blocked: true,
                message:
                    "🚫 Your driver account is blocked by UDAN Admin."
            });
        }

        req.user = user;

        next();

    } catch (error) {

        return res.status(401).json({
            success: false,
            message:
                "Invalid or expired token."
        });
    }
}

function requireRole(...roles) {
    return (req, res, next) => {
        if (
            req.user &&
            roles.includes(
                req.user.role
            )
        ) {
            return next();
        }

        return res.status(403).json({
            success: false,
            message:
                "Access denied."
        });
    };
}

/* =====================================================
   TEMP OTP STORAGE
   For current development/testing flow
===================================================== */

const otpStore = new Map();

function generateOTP() {
    return String(
        Math.floor(
            100000 +
            Math.random() * 900000
        )
    );
}

function saveOTP(
    email,
    purpose,
    otp
) {
    const key =
        `${purpose}:${email}`;

    otpStore.set(
        key,
        {
            otp,
            expiresAt:
                Date.now() +
                10 * 60 * 1000
        }
    );
}

function verifyStoredOTP(
    email,
    purpose,
    otp
) {
    const key =
        `${purpose}:${email}`;

    const record =
        otpStore.get(key);

    if (!record) {
        return false;
    }

    if (
        Date.now() >
        record.expiresAt
    ) {
        otpStore.delete(key);
        return false;
    }

    if (
        String(record.otp) !==
        String(otp)
    ) {
        return false;
    }

    otpStore.delete(key);

    return true;
}

/* =====================================================
   HOME
===================================================== */

app.get("/", (req, res) => {

    sendPage(
        res,
        ["index.html"],
        "UDAN CAB Backend is running."
    );

});

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
                vehicleType,
                vehicleNumber,
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
                ![
                    "passenger",
                    "driver",
                    "admin"
                ].includes(
                    finalRole
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid role."
                });
            }

            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();

            const existing =
                await User.findOne({
                    email: cleanEmail
                });

            if (existing) {
                return res.status(409).json({
                    success: false,
                    message:
                        "Email is already registered."
                });
            }

            if (
                finalRole === "driver" &&
                (!vehicleNumber ||
                    !license)
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Driver vehicle number and license are required."
                });
            }

            const hashed =
                await bcrypt.hash(
                    String(password),
                    12
                );

            const user =
                await User.create({

                    name:
                        name ||
                        "UDAN User",

                    email:
                        cleanEmail,

                    password:
                        hashed,

                    role:
                        finalRole,

                    city:
                        city ||
                        "Nalanda",

                    vehicleType:
                        vehicleType ||
                        "",

                    vehicleNumber:
                        vehicleNumber ||
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

            return res.status(201).json({

                success: true,

                message:
                    "Registration successful.",

                user:
                    safeUser(user),

                token:
                    createToken(user)

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
                    email:
                        cleanEmail,
                    role:
                        finalRole
                });

            if (!user) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid email, password or role."
                });
            }

            if (
                user.blocked === true
            ) {
                return res.status(403).json({
                    success: false,
                    blocked: true,
                    message:
                        "🚫 Your account is blocked."
                });
            }

            const match =
                await bcrypt.compare(
                    String(password),
                    user.password
                );

            if (!match) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid email, password or role."
                });
            }

            return res.json({

                success: true,

                message:
                    "Login successful.",

                token:
                    createToken(user),

                user:
                    safeUser(user)

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
                error:
                    error.message
            });
        }
    }
);

/* =====================================================
   SEND OTP
===================================================== */

app.post(
    "/api/send-otp",
    async (req, res) => {

        try {

            const {
                email,
                purpose
            } = req.body;

            if (!email || !purpose) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email and OTP purpose are required."
                });
            }

            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();

            const allowedPurposes = [
                "register",
                "login",
                "forgot"
            ];

            if (
                !allowedPurposes.includes(
                    purpose
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid OTP purpose."
                });
            }

            if (
                purpose === "register"
            ) {

                const exists =
                    await User.findOne({
                        email:
                            cleanEmail
                    });

                if (exists) {
                    return res.status(409).json({
                        success: false,
                        message:
                            "Email is already registered."
                    });
                }
            }

            if (
                purpose === "login" ||
                purpose === "forgot"
            ) {

                const exists =
                    await User.findOne({
                        email:
                            cleanEmail
                    });

                if (!exists) {
                    return res.status(404).json({
                        success: false,
                        message:
                            "No account found with this email."
                    });
                }
            }

            const otp =
                generateOTP();

            saveOTP(
                cleanEmail,
                purpose,
                otp
            );

            console.log(
                `🧪 OTP [${purpose}] ${cleanEmail}: ${otp}`
            );

            return res.json({

                success: true,

                message:
                    "OTP generated successfully.",

                developmentOTP:
                    otp

            });

        } catch (error) {

            console.error(
                "SEND OTP ERROR:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to send OTP."
            });
        }
    }
);

/* =====================================================
   VERIFY OTP
===================================================== */

app.post(
    "/api/verify-otp",
    async (req, res) => {

        try {

            const {
                email,
                otp,
                purpose
            } = req.body;

            if (
                !email ||
                !otp ||
                !purpose
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email, OTP and purpose are required."
                });
            }

            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();

            const valid =
                verifyStoredOTP(
                    cleanEmail,
                    purpose,
                    otp
                );

            if (!valid) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid or expired OTP."
                });
            }

            const response = {
                success: true,
                message:
                    "OTP verified successfully."
            };

            if (
                purpose === "login"
            ) {

                const user =
                    await User.findOne({
                        email:
                            cleanEmail
                    });

                if (user) {
                    response.token =
                        createToken(user);

                    response.user =
                        safeUser(user);
                }
            }

            return res.json(response);

        } catch (error) {

            console.error(
                "VERIFY OTP ERROR:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "OTP verification failed."
            });
        }
    }
);

/* =====================================================
   FORGOT PASSWORD
===================================================== */

app.post(
    "/api/forgot-password",
    async (req, res) => {

        try {

            const email =
                String(
                    req.body.email || ""
                )
                    .trim()
                    .toLowerCase();

            if (!email) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email is required."
                });
            }

            const user =
                await User.findOne({
                    email
                });

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Account not found."
                });
            }

            const otp =
                generateOTP();

            saveOTP(
                email,
                "forgot",
                otp
            );

            console.log(
                `🧪 Forgot Password OTP ${email}: ${otp}`
            );

            return res.json({

                success: true,

                message:
                    "Password reset OTP generated.",

                developmentOTP:
                    otp

            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                message:
                    "Unable to send reset OTP."
            });
        }
    }
);

/* =====================================================
   RESET PASSWORD
===================================================== */

app.post(
    "/api/reset-password",
    async (req, res) => {

        try {

            const {
                email,
                otp,
                newPassword,
                password
            } = req.body;

            const finalPassword =
                newPassword ||
                password;

            if (
                !email ||
                !otp ||
                !finalPassword
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email, OTP and new password are required."
                });
            }

            if (
                String(finalPassword)
                    .length < 6
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Password must contain at least 6 characters."
                });
            }

            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();

            const valid =
                verifyStoredOTP(
                    cleanEmail,
                    "forgot",
                    otp
                );

            if (!valid) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid or expired OTP."
                });
            }

            const user =
                await User.findOne({
                    email:
                        cleanEmail
                });

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Account not found."
                });
            }

            user.password =
                await bcrypt.hash(
                    String(finalPassword),
                    12
                );

            await user.save();

            return res.json({
                success: true,
                message:
                    "Password reset successfully."
            });

        } catch (error) {

            console.error(
                "RESET PASSWORD ERROR:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to reset password."
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
    (req, res) => {

        res.json({
            success: true,
            user:
                safeUser(req.user)
        });

    }
);

/* =====================================================
   DRIVER STATUS
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
                    lat: null,
                    lng: null,
                    accuracy: null,
                    updatedAt: null
                };
            }

            await req.user.save();

            res.json({

                success: true,

                message:
                    online
                        ? "Driver is online."
                        : "Driver is offline.",

                driver: {
                    id:
                        req.user._id,
                    online
                }

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

/* =====================================================
   GENERAL LOCATION UPDATE
===================================================== */

app.post(
    "/api/location/update",
    authenticate,
    async (req, res) => {

        try {

            const lat =
                toNumber(
                    req.body.latitude ??
                    req.body.lat
                );

            const lng =
                toNumber(
                    req.body.longitude ??
                    req.body.lng
                );

            const accuracy =
                toNumber(
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

                updatedAt:
                    new Date()

            };

            if (
                req.user.role ===
                "driver"
            ) {
                req.user.online =
                    true;
            }

            await req.user.save();

            res.json({

                success: true,

                message:
                    "Location updated.",

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
                toNumber(
                    req.query.lat ??
                    req.query.latitude
                );

            const lng =
                toNumber(
                    req.query.lng ??
                    req.query.longitude
                );

            const serviceArea =
                String(
                    req.query.serviceArea ||
                    req.user.city ||
                    "Nalanda"
                ).trim();

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
                        "Valid latitude and longitude are required.",
                    drivers: []
                });
            }

            const query = {

                role:
                    "driver",

                online:
                    true,

                blocked:
                    { $ne: true },

                city:
                    serviceArea

            };

            if (vehicleType) {
                query.vehicleType =
                    vehicleType;
            }

            const drivers =
                await User.find(
                    query
                )
                    .select(
                        "name email vehicleType vehicleNumber rating location city online blocked"
                    )
                    .lean();

            const result =
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

                            const distance =
                                distanceKm(
                                    lat,
                                    lng,
                                    Number(
                                        driver.location.lat
                                    ),
                                    Number(
                                        driver.location.lng
                                    )
                                );

                            return {

                                ...driver,

                                latitude:
                                    driver.location.lat,

                                longitude:
                                    driver.location.lng,

                                distanceKm:
                                    Number(
                                        distance.toFixed(
                                            2
                                        )
                                    )

                            };
                        }
                    )

                    .sort(
                        (a, b) =>
                            a.distanceKm -
                            b.distanceKm
                    );

            res.json({

                success:
                    true,

                serviceArea,

                vehicleType:
                    vehicleType ||
                    null,

                drivers:
                    result

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

/* =====================================================
   CREATE RIDE / PARCEL RIDE
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
                vehicleType,
                fare,
                parcelType,
                parcelVehicleType,
                parcelWeight,
                serviceArea,
                pickupLatitude,
                pickupLongitude,
                passengerLatitude,
                passengerLongitude,
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

            const pLat =
                toNumber(
                    pickupLatitude ??
                    passengerLatitude
                );

            const pLng =
                toNumber(
                    pickupLongitude ??
                    passengerLongitude
                );

            const dLat =
                toNumber(
                    destinationLatitude
                );

            const dLng =
                toNumber(
                    destinationLongitude
                );

            const finalVehicleType =
                parcelVehicleType ||
                vehicleType ||
                null;

            const ride =
                await Ride.create({

                    userId:
                        req.user._id,

                    pickup:
                        String(pickup)
                            .trim(),

                    destination:
                        String(destination)
                            .trim(),

                    cabType:
                        String(cabType)
                            .trim(),

                    fare:
                        Number(fare),

                    vehicleType:
                        finalVehicleType,

                    parcelType:
                        parcelType ||
                        null,

                    parcelWeight:
                        parcelWeight !==
                        undefined
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
                            pLat,

                        lng:
                            pLng,

                        accuracy:
                            null,

                        updatedAt:
                            new Date()

                    },

                    destinationLocation: {

                        lat:
                            dLat,

                        lng:
                            dLng

                    }

                });

            /*
               Find nearest suitable driver.
            */

            if (
                pLat !== null &&
                pLng !== null
            ) {

                const driverQuery = {

                    role:
                        "driver",

                    online:
                        true,

                    blocked:
                        { $ne: true },

                    city:
                        ride.serviceArea

                };

                if (
                    finalVehicleType
                ) {

                    driverQuery.vehicleType =
                        finalVehicleType;
                }

                let drivers =
                    await User.find(
                        driverQuery
                    ).lean();

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

                                const distance =
                                    distanceKm(
                                        pLat,
                                        pLng,
                                        Number(
                                            driver.location.lat
                                        ),
                                        Number(
                                            driver.location.lng
                                        )
                                    );

                                return {
                                    driver,
                                    distance
                                };
                            }
                        )
                        .sort(
                            (a, b) =>
                                a.distance -
                                b.distance
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
                                .distance
                                .toFixed(
                                    2
                                )
                        );

                    await ride.save();
                }
            }

            res.status(201).json({

                success:
                    true,

                message:
                    "Ride booked successfully.",

                ride

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

                error:
                    error.message

            });
        }
    }
);

/* =====================================================
   GET RIDES
   Passenger = own rides
   Driver = available rides
   Admin = all rides
===================================================== */

app.get(
    "/api/rides",
    authenticate,
    async (req, res) => {

        try {

            let filter = {};

            if (
                req.user.role ===
                "passenger"
            ) {

                filter = {
                    userId:
                        req.user._id
                };

            } else if (
                req.user.role ===
                "driver"
            ) {

                filter = {

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

                };

            } else if (
                req.user.role ===
                "admin"
            ) {

                filter = {};

            } else {

                return res.status(403).json({
                    success: false,
                    message:
                        "Access denied."
                });
            }

            const rides =
                await Ride.find(
                    filter
                )

                    .populate(
                        "userId",
                        "name email city location"
                    )

                    .populate(
                        "driverId",
                        "name email vehicleNumber vehicleType rating location online blocked"
                    )

                    .sort({
                        createdAt:
                            -1
                    });

            res.json({
                success: true,
                rides
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
                success: true,
                rides
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message:
                    "Unable to load available rides.",
                rides: []
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
                success: true,
                rides
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

/* =====================================================
   DRIVER PARCEL REQUESTS
===================================================== */

app.get(
    "/api/driver/:id/requests",
    authenticate,
    requireRole("driver"),
    async (req, res) => {

        try {

            if (
                req.params.id !==
                req.user._id.toString()
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        "Access denied."
                });
            }

            const rides =
                await Ride.find({

                    cabType:
                        "Parcel Delivery",

                    status: {
                        $nin: [
                            "Completed",
                            "Cancelled"
                        ]
                    },

                    $or: [

                        {
                            assignedDriverId:
                                req.user._id
                        },

                        {
                            driverId:
                                req.user._id
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
                success: true,
                rides
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message:
                    "Unable to load parcel requests.",
                rides: []
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
                ride.status !==
                "Searching for driver"
            ) {
                return res.status(409).json({
                    success: false,
                    message:
                        "This ride is no longer available."
                });
            }

            if (
                ride.driverId
            ) {
                return res.status(409).json({
                    success: false,
                    message:
                        "This ride has already been accepted."
                });
            }

            if (
                ride.assignedDriverId &&
                ride.assignedDriverId.toString() !==
                req.user._id.toString()
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        "This ride is assigned to another nearby driver."
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
                    null &&
                req.user.location.lng !==
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

                success:
                    true,

                message:
                    "🚕 Ride accepted successfully.",

                ride

            });

        } catch (error) {

            console.error(
                "ACCEPT RIDE ERROR:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Unable to accept ride.",

                error:
                    error.message

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

            if (
                !isObjectId(
                    req.params.id
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid ride ID."
                });
            }

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
                    success: false,
                    message:
                        "Ride not found."
                });
            }

            const passenger =
                ride.userId &&
                ride.userId._id.toString() ===
                req.user._id.toString();

            const driver =
                ride.driverId &&
                ride.driverId._id.toString() ===
                req.user._id.toString();

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
                ride
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
                    success: false,
                    message:
                        "Ride not found."
                });
            }

            if (
                ride.status !==
                "Driver accepted" &&
                ride.status !==
                "Driver assigned"
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Ride cannot be started right now."
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

                ride

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

/* OLD FRONTEND START METHOD */
app.post(
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
                message:
                    "🚕 Ride started.",
                ride
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
                    success: false,
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

                ride

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

/* OLD FRONTEND COMPLETE METHOD */
app.post(
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

                success:
                    true,

                message:
                    "✅ Ride completed successfully.",

                ride

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
                    success: false,
                    message:
                        "Ride not found."
                });
            }

            const allowed =
                ride.userId?.toString() ===
                    req.user._id.toString() ||

                ride.driverId?.toString() ===
                    req.user._id.toString() ||

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

                success:
                    true,

                message:
                    "Ride cancelled.",

                ride

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

/* OLD FRONTEND CANCEL METHOD */
app.post(
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
                ride.userId?.toString() ===
                    req.user._id.toString() ||

                ride.driverId?.toString() ===
                    req.user._id.toString() ||

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
                message:
                    "Ride cancelled.",
                ride
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

/* =====================================================
   PASSENGER LOCATION
===================================================== */

app.patch(
    "/api/rides/:id/passenger-location",
    authenticate,
    requireRole("passenger"),
    async (req, res) => {

        try {

            const lat =
                toNumber(
                    req.body.latitude ??
                    req.body.lat
                );

            const lng =
                toNumber(
                    req.body.longitude ??
                    req.body.lng
                );

            const accuracy =
                toNumber(
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

                accuracy,

                updatedAt:
                    new Date()

            };

            await ride.save();

            req.user.location =
                ride.passengerLocation;

            await req.user.save();

            res.json({

                success:
                    true,

                message:
                    "Passenger location updated.",

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

/* =====================================================
   DRIVER LOCATION
===================================================== */

app.patch(
    "/api/rides/:id/driver-location",
    authenticate,
    requireRole("driver"),
    async (req, res) => {

        try {

            const lat =
                toNumber(
                    req.body.latitude ??
                    req.body.lat
                );

            const lng =
                toNumber(
                    req.body.longitude ??
                    req.body.lng
                );

            const accuracy =
                toNumber(
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

                accuracy,

                updatedAt:
                    new Date()

            };

            await ride.save();

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

            res.json({

                success:
                    true,

                message:
                    "Driver location updated.",

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

/* OLD DRIVER GPS METHOD */
app.post(
    "/api/rides/:id/driver-location",
    authenticate,
    requireRole("driver"),
    async (req, res) => {

        try {

            const lat =
                toNumber(
                    req.body.latitude ??
                    req.body.lat
                );

            const lng =
                toNumber(
                    req.body.longitude ??
                    req.body.lng
                );

            const accuracy =
                toNumber(
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
                accuracy,
                updatedAt:
                    new Date()

            };

            await ride.save();

            req.user.location =
                ride.driverLocation;

            req.user.online =
                true;

            await req.user.save();

            res.json({

                success:
                    true,

                message:
                    "Driver location updated.",

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

/* =====================================================
   OLD GENERIC LOCATION ROUTE
   Works for passenger OR assigned driver
===================================================== */

app.post(
    "/api/rides/:id/location",
    authenticate,
    async (req, res) => {

        try {

            const lat =
                toNumber(
                    req.body.latitude ??
                    req.body.lat
                );

            const lng =
                toNumber(
                    req.body.longitude ??
                    req.body.lng
                );

            const accuracy =
                toNumber(
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

            const passenger =
                ride.userId?.toString() ===
                req.user._id.toString();

            const driver =
                ride.driverId?.toString() ===
                req.user._id.toString();

            if (
                !passenger &&
                !driver
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        "You are not assigned to this ride."
                });
            }

            const location = {

                lat,
                lng,
                accuracy,
                updatedAt:
                    new Date()

            };

            if (passenger) {

                ride.passengerLocation =
                    location;

                req.user.location =
                    location;

            } else if (driver) {

                ride.driverLocation =
                    location;

                req.user.location =
                    location;

                req.user.online =
                    true;

            }

            await ride.save();
            await req.user.save();

            res.json({

                success:
                    true,

                message:
                    "Location updated.",

                location

            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message:
                    "Unable to update ride location."
            });
        }
    }
);

/* =====================================================
   LIVE LOCATION
===================================================== */

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

            res.json({

                success:
                    true,

                rideId:
                    ride._id,

                status:
                    ride.status,

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

/* =====================================================
   ADMIN - PASSENGERS
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

                passengers

            });

        } catch (error) {

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
   ADMIN - DRIVERS
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

                drivers

            });

        } catch (error) {

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
   ADMIN - ALL USERS
===================================================== */

app.get(
    "/api/admin/users",
    authenticate,
    requireRole("admin"),
    async (req, res) => {

        try {

            const users =
                await User.find({})
                    .select("-password")
                    .sort({
                        createdAt:
                            -1
                    })
                    .lean();

            res.json({
                success: true,
                users
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message:
                    "Unable to load users.",
                users: []
            });
        }
    }
);

/* =====================================================
   ADMIN - ALL RIDES
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

                rides

            });

        } catch (error) {

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
   ADMIN - BLOCK DRIVER
===================================================== */

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

                        role:
                            "driver"

                    },

                    {
                        $set: {

                            blocked:
                                true,

                            blockedReason:
                                req.body?.reason ||
                                "Blocked by UDAN Admin",

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
                    success: false,
                    message:
                        "Driver not found."
                });
            }

            res.json({

                success:
                    true,

                message:
                    "🚫 Driver blocked successfully.",

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

/* =====================================================
   ADMIN - UNBLOCK DRIVER
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
                    success: false,
                    message:
                        "Driver not found."
                });
            }

            res.json({

                success:
                    true,

                message:
                    "✅ Driver unblocked successfully.",

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

/* =====================================================
   ADMIN - REMOVE DRIVER
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

                success:
                    true,

                message:
                    "🗑️ Driver removed successfully."

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

        } catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to load statistics."

            });
        }
    }
);

/* =====================================================
   ALL LIVE LOCATIONS - ADMIN
===================================================== */

app.get(
    "/api/live-locations",
    authenticate,
    requireRole("admin"),
    async (req, res) => {

        try {

            const rides =
                await Ride.find({

                    status: {
                        $nin: [
                            "Completed",
                            "Cancelled"
                        ]
                    }

                })
                    .lean();

            const locations =
                rides.map(
                    ride => ({

                        rideId:
                            ride._id,

                        status:
                            ride.status,

                        passengerId:
                            ride.userId,

                        driverId:
                            ride.driverId,

                        vehicleType:
                            ride.vehicleType,

                        passengerLocation:
                            ride.passengerLocation,

                        driverLocation:
                            ride.driverLocation

                    })
                );

            res.json({

                success:
                    true,

                serviceArea:
                    "Nalanda",

                locations

            });

        } catch (error) {

            res.status(500).json({

                success:
                    false,

                message:
                    "Unable to load live locations.",

                locations:
                    []

            });
        }
    }
);

/* =====================================================
   SERVICE AREAS
===================================================== */

app.get(
    "/api/service-areas",
    (req, res) => {

        res.json({

            success:
                true,

            areas: [

                {
                    name:
                        "Nalanda",

                    active:
                        true

                }

            ]

        });

    }
);

/* =====================================================
   FRONTEND ROUTES
   IMPORTANT:
   Do NOT create Express routes containing
   dashboard(1).html / admin(1).html etc.
   Express 5 treats parentheses as route syntax.

   express.static() serves those actual filenames.
===================================================== */

app.get(
    "/login.html",
    (req, res) => {

        sendPage(

            res,

            [
                "login.html"
            ],

            "login.html not found."

        );
    }
);

app.get(
    "/dashboard.html",
    (req, res) => {

        sendPage(

            res,

            [
                "dashboard.html",
                "dashboard(1).html"
            ],

            "dashboard.html not found."

        );
    }
);

app.get(
    "/driver-dashboard.html",
    (req, res) => {

        sendPage(

            res,

            [
                "driver-dashboard.html",
                "driver-dashboard(1).html"
            ],

            "driver-dashboard.html not found."

        );
    }
);

app.get(
    "/admin.html",
    (req, res) => {

        sendPage(

            res,

            [
                "admin.html",
                "admin(1).html"
            ],

            "admin.html not found."

        );
    }
);

app.get(
    "/parcel.html",
    (req, res) => {

        sendPage(

            res,

            [
                "parcel.html",
                "parcel(1).html"
            ],

            "parcel.html not found."

        );
    }
);

/* =====================================================
   API 404
===================================================== */

app.use(
    "/api",
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

        if (
            res.headersSent
        ) {
            return next(error);
        }

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
            "=========================================="
        );

        console.log(
            `🚕 UDAN CAB SERVER RUNNING ON PORT ${PORT}`
        );

        console.log(
            "✅ MongoDB"
        );

        console.log(
            "✅ Login / Register"
        );

        console.log(
            "✅ OTP system"
        );

        console.log(
            "✅ Passenger rides"
        );

        console.log(
            "✅ Driver rides"
        );

        console.log(
            "✅ Parcel delivery"
        );

        console.log(
            "✅ GPS / Live location"
        );

        console.log(
            "✅ Admin dashboard APIs"
        );

        console.log(
            "✅ Frontend static files"
        );

        console.log(
            "=========================================="
        );

    }
);
