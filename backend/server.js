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

/* =========================================================
   BASIC CHECK
========================================================= */

if (!MONGODB_URI) {
    console.error("❌ MONGODB_URI is missing.");
    process.exit(1);
}

if (!JWT_SECRET) {
    console.error("❌ JWT_SECRET is missing.");
    process.exit(1);
}

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
    cors({
        origin: true,
        credentials: true
    })
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   FRONTEND
   server.js:
   UDAN-CAB/backend/server.js

   HTML:
   UDAN-CAB/index.html
   UDAN-CAB/login.html
   UDAN-CAB/login(2).html
   UDAN-CAB/dashboard(1).html
   UDAN-CAB/driver-dashboard(1).html
   UDAN-CAB/admin(1).html
   UDAN-CAB/parcel(1).html
========================================================= */

const FRONTEND_DIR = path.join(__dirname, "..");

/* =========================================================
   MONGODB
========================================================= */

mongoose
    .connect(MONGODB_URI)
    .then(() => {
        console.log("======================================");
        console.log("✅ MongoDB Connected Successfully");
        console.log("🗄️ Database: udan");
        console.log("======================================");
    })
    .catch((error) => {
        console.error("❌ MongoDB Connection Failed");
        console.error(error.message);
    });

/* =========================================================
   HELPERS
========================================================= */

function normalizeRole(role) {
    if (role === "user") {
        return "passenger";
    }

    return role;
}

function frontendRole(role) {
    if (role === "passenger") {
        return "user";
    }

    return role;
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

function safeUser(user) {
    return {
        id: String(user._id),
        _id: String(user._id),
        name: user.name || "UDAN User",
        email: user.email,
        role: frontendRole(user.role),
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

function numberOrNull(value) {
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

    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    return R * c;
}

/* =========================================================
   AUTH MIDDLEWARE
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

        const decoded = jwt.verify(token, JWT_SECRET);

        const user = await User.findById(decoded.id);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "User account not found."
            });
        }

        if (user.role === "driver" && user.blocked === true) {
            return res.status(403).json({
                success: false,
                blocked: true,
                message:
                    "🚫 Your driver account has been blocked by UDAN Admin."
            });
        }

        req.user = user;

        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired authentication token."
        });
    }
}

function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: "You are not authorized for this action."
            });
        }

        next();
    };
}

/* =========================================================
   FRONTEND HELPERS
========================================================= */

function serveFirstExisting(res, filenames, notFoundMessage) {
    for (const filename of filenames) {
        const fullPath = path.join(FRONTEND_DIR, filename);

        if (fs.existsSync(fullPath)) {
            return res.sendFile(fullPath);
        }
    }

    return res.status(404).send(notFoundMessage);
}

/*
   IMPORTANT:
   Do NOT create routes such as:
   app.get("/dashboard(1).html", ...)

   The "(1)" is ONLY an actual filename.
*/

app.use(express.static(FRONTEND_DIR));

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
    serveFirstExisting(
        res,
        ["index.html"],
        "index.html not found"
    );
});

/* =========================================================
   SAFE HTML ALIASES
========================================================= */

app.get("/login.html", (req, res) => {
    serveFirstExisting(
        res,
        [
            "login.html",
            "login(2).html",
            "login(1).html"
        ],
        "login.html not found"
    );
});

app.get("/dashboard.html", (req, res) => {
    serveFirstExisting(
        res,
        [
            "dashboard.html",
            "dashboard(1).html"
        ],
        "dashboard.html not found"
    );
});

app.get("/driver-dashboard.html", (req, res) => {
    serveFirstExisting(
        res,
        [
            "driver-dashboard.html",
            "driver-dashboard(1).html"
        ],
        "driver-dashboard.html not found"
    );
});

app.get("/admin.html", (req, res) => {
    serveFirstExisting(
        res,
        [
            "admin.html",
            "admin(1).html"
        ],
        "admin.html not found"
    );
});

app.get("/parcel.html", (req, res) => {
    serveFirstExisting(
        res,
        [
            "parcel.html",
            "parcel(1).html"
        ],
        "parcel.html not found"
    );
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", async (req, res) => {
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

        if (!email || !password || !role) {
            return res.status(400).json({
                success: false,
                message:
                    "Email, password and role are required."
            });
        }

        const finalRole = normalizeRole(role);

        if (
            ![
                "passenger",
                "driver",
                "admin"
            ].includes(finalRole)
        ) {
            return res.status(400).json({
                success: false,
                message: "Invalid role."
            });
        }

        const cleanEmail = String(email)
            .trim()
            .toLowerCase();

        const existing = await User.findOne({
            email: cleanEmail
        });

        if (existing) {
            return res.status(409).json({
                success: false,
                message: "This email is already registered."
            });
        }

        const hashedPassword = await bcrypt.hash(
            String(password),
            12
        );

        const user = await User.create({
            name: name || "UDAN User",
            email: cleanEmail,
            password: hashedPassword,
            role: finalRole,
            city: city || "Nalanda",
            vehicleNumber: vehicleNumber || "",
            vehicleType: vehicleType || "",
            license: license || "",
            rating: 4.8,
            online: false,
            blocked: false,
            blockedReason: "",
            blockedAt: null
        });

        return res.status(201).json({
            success: true,
            message: "Registration successful!",
            user: safeUser(user)
        });
    } catch (error) {
        console.error("REGISTER ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Registration failed.",
            error: error.message
        });
    }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
    try {
        const {
            email,
            password,
            role
        } = req.body;

        if (!email || !password || !role) {
            return res.status(400).json({
                success: false,
                message:
                    "Email, password and role are required."
            });
        }

        const finalRole = normalizeRole(role);

        const cleanEmail = String(email)
            .trim()
            .toLowerCase();

        const user = await User.findOne({
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
            user.blocked === true
        ) {
            return res.status(403).json({
                success: false,
                blocked: true,
                message:
                    "🚫 Your driver account has been blocked by UDAN Admin."
            });
        }

        const correct = await bcrypt.compare(
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

        const token = createToken(user);

        return res.json({
            success: true,
            message: "Login successful!",
            token,
            user: safeUser(user)
        });
    } catch (error) {
        console.error("LOGIN ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Login failed.",
            error: error.message
        });
    }
});

/* =========================================================
   OTP
   Prototype in-memory OTP store.
========================================================= */

const otpStore = new Map();

function createOtp() {
    return String(
        Math.floor(100000 + Math.random() * 900000)
    );
}

app.post("/api/send-otp", async (req, res) => {
    try {
        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();

        const purpose =
            String(req.body.purpose || "login")
                .trim()
                .toLowerCase();

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required."
            });
        }

        const otp = createOtp();

        otpStore.set(
            `${purpose}:${email}`,
            {
                otp,
                expiresAt: Date.now() + 5 * 60 * 1000
            }
        );

        /*
          Real email/SMS provider abhi connected nahi hai.
          Development ke liye OTP response me diya ja raha hai.
        */

        console.log(
            `🔐 OTP for ${email} (${purpose}): ${otp}`
        );

        return res.json({
            success: true,
            message: "OTP generated successfully.",
            email,
            purpose,
            otp
        });
    } catch (error) {
        console.error("SEND OTP ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to send OTP."
        });
    }
});

app.post("/api/verify-otp", async (req, res) => {
    try {
        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();

        const otp = String(req.body.otp || "")
            .trim();

        const purpose =
            String(req.body.purpose || "login")
                .trim()
                .toLowerCase();

        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: "Email and OTP are required."
            });
        }

        const key = `${purpose}:${email}`;

        const record = otpStore.get(key);

        if (!record) {
            return res.status(400).json({
                success: false,
                message: "OTP not found. Please request a new OTP."
            });
        }

        if (Date.now() > record.expiresAt) {
            otpStore.delete(key);

            return res.status(400).json({
                success: false,
                message: "OTP expired."
            });
        }

        if (record.otp !== otp) {
            return res.status(400).json({
                success: false,
                message: "Invalid OTP."
            });
        }

        otpStore.delete(key);

        /*
          Login purpose:
          token bhi return karte hain.
        */

        if (purpose === "login") {
            const user = await User.findOne({
                email
            });

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "No account found with this email."
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
                        "🚫 Your driver account has been blocked by UDAN Admin."
                });
            }

            const token = createToken(user);

            return res.json({
                success: true,
                message: "OTP verified successfully.",
                verified: true,
                token,
                user: safeUser(user)
            });
        }

        return res.json({
            success: true,
            message: "OTP verified successfully.",
            verified: true
        });
    } catch (error) {
        console.error("VERIFY OTP ERROR:", error);

        return res.status(500).json({
            success: false,
            message: "Unable to verify OTP."
        });
    }
});

/* =========================================================
   FORGOT PASSWORD
========================================================= */

app.post("/api/forgot-password", async (req, res) => {
    try {
        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required."
            });
        }

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({
                success: false,
                message:
                    "No account found with this email."
            });
        }

        const otp = createOtp();

        otpStore.set(
            `reset:${email}`,
            {
                otp,
                expiresAt: Date.now() + 5 * 60 * 1000
            }
        );

        console.log(
            `🔐 PASSWORD RESET OTP for ${email}: ${otp}`
        );

        return res.json({
            success: true,
            message: "Password reset OTP generated.",
            otp
        });
    } catch (error) {
        console.error(
            "FORGOT PASSWORD ERROR:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Unable to process request."
        });
    }
});

app.post("/api/reset-password", async (req, res) => {
    try {
        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();

        const otp = String(req.body.otp || "")
            .trim();

        const newPassword = String(
            req.body.newPassword ||
            req.body.password ||
            ""
        );

        if (!email || !otp || !newPassword) {
            return res.status(400).json({
                success: false,
                message:
                    "Email, OTP and new password are required."
            });
        }

        if (newPassword.length < 4) {
            return res.status(400).json({
                success: false,
                message:
                    "New password must be at least 4 characters."
            });
        }

        const key = `reset:${email}`;
        const record = otpStore.get(key);

        if (!record) {
            return res.status(400).json({
                success: false,
                message: "Reset OTP not found."
            });
        }

        if (Date.now() > record.expiresAt) {
            otpStore.delete(key);

            return res.status(400).json({
                success: false,
                message: "OTP expired."
            });
        }

        if (record.otp !== otp) {
            return res.status(400).json({
                success: false,
                message: "Invalid OTP."
            });
        }

        const user = await User.findOne({
            email
        });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found."
            });
        }

        user.password = await bcrypt.hash(
            newPassword,
            12
        );

        await user.save();

        otpStore.delete(key);

        return res.json({
            success: true,
            message: "Password reset successfully."
        });
    } catch (error) {
        console.error(
            "RESET PASSWORD ERROR:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Unable to reset password."
        });
    }
});

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
   DRIVER ONLINE / OFFLINE
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
                online: req.user.online,
                message: online
                    ? "Driver is online."
                    : "Driver is offline."
            });
        } catch (error) {
            console.error(
                "DRIVER STATUS ERROR:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to update driver status."
            });
        }
    }
);

/* =========================================================
   GENERAL USER LOCATION
========================================================= */

app.post(
    "/api/location/update",
    authenticate,
    async (req, res) => {
        try {
            const lat = numberOrNull(
                req.body.latitude ?? req.body.lat
            );

            const lng = numberOrNull(
                req.body.longitude ?? req.body.lng
            );

            const accuracy = numberOrNull(
                req.body.accuracy
            );

            if (lat === null || lng === null) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid location."
                });
            }

            req.user.location = {
                lat,
                lng,
                accuracy,
                updatedAt: new Date()
            };

            if (req.user.role === "driver") {
                req.user.online = true;
            }

            await req.user.save();

            res.json({
                success: true,
                message: "Location updated.",
                location: req.user.location
            });
        } catch (error) {
            console.error(
                "LOCATION UPDATE ERROR:",
                error
            );

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
            const lat = numberOrNull(
                req.query.lat ??
                req.query.latitude
            );

            const lng = numberOrNull(
                req.query.lng ??
                req.query.longitude
            );

            const vehicleType =
                String(
                    req.query.vehicleType || ""
                ).trim();

            const city =
                String(
                    req.query.serviceArea ||
                    req.user.city ||
                    "Nalanda"
                ).trim();

            if (lat === null || lng === null) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Valid location is required.",
                    drivers: []
                });
            }

            let drivers = await User.find({
                role: "driver",
                online: true,
                blocked: { $ne: true },
                city
            })
                .select(
                    "name email vehicleType vehicleNumber rating location city online"
                )
                .lean();

            if (vehicleType) {
                drivers = drivers.filter(
                    driver =>
                        !driver.vehicleType ||
                        driver.vehicleType === vehicleType
                );
            }

            drivers = drivers
                .filter(
                    driver =>
                        driver.location &&
                        Number.isFinite(
                            Number(driver.location.lat)
                        ) &&
                        Number.isFinite(
                            Number(driver.location.lng)
                        )
                )
                .map(driver => ({
                    ...driver,
                    distanceKm: Number(
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
            console.error(
                "NEARBY DRIVERS ERROR:",
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
   BOOK RIDE
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

            const pickupLat =
                numberOrNull(
                    pickupLatitude ??
                    passengerLatitude
                );

            const pickupLng =
                numberOrNull(
                    pickupLongitude ??
                    passengerLongitude
                );

            const destinationLat =
                numberOrNull(
                    destinationLatitude
                );

            const destinationLng =
                numberOrNull(
                    destinationLongitude
                );

            const ride = await Ride.create({
                userId: req.user._id,

                pickup: String(pickup).trim(),
                destination: String(destination).trim(),

                cabType: String(cabType),

                fare: Number(fare),

                vehicleType:
                    vehicleType || null,

                parcelType:
                    parcelType || null,

                parcelWeight:
                    parcelWeight !== undefined
                        ? String(parcelWeight)
                        : null,

                serviceArea:
                    serviceArea ||
                    req.user.city ||
                    "Nalanda",

                status:
                    "Searching for driver",

                passengerLocation: {
                    lat: pickupLat,
                    lng: pickupLng,
                    accuracy: null,
                    updatedAt: new Date()
                },

                destinationLocation: {
                    lat: destinationLat,
                    lng: destinationLng
                }
            });

            /* =================================================
               AUTO ASSIGN NEAREST DRIVER
            ================================================= */

            if (
                pickupLat !== null &&
                pickupLng !== null
            ) {
                let drivers = await User.find({
                    role: "driver",
                    online: true,
                    blocked: { $ne: true },
                    city:
                        ride.serviceArea
                }).lean();

                /*
                   Vehicle type exact match available
                   ho to use karo.
                   Empty driver vehicleType ko reject nahi
                   kar rahe.
                */

                if (ride.vehicleType) {
                    drivers = drivers.filter(
                        driver =>
                            !driver.vehicleType ||
                            driver.vehicleType ===
                                ride.vehicleType
                    );
                }

                drivers = drivers
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
                        distanceKm:
                            distanceKm(
                                pickupLat,
                                pickupLng,
                                driver.location.lat,
                                driver.location.lng
                            )
                    }))
                    .sort(
                        (a, b) =>
                            a.distanceKm -
                            b.distanceKm
                    );

                if (drivers.length > 0) {
                    ride.assignedDriverId =
                        drivers[0].driver._id;

                    ride.assignedDistanceKm =
                        Number(
                            drivers[0].distanceKm.toFixed(
                                2
                            )
                        );

                    await ride.save();
                }
            }

            return res.status(201).json({
                success: true,
                message:
                    "Ride booked successfully!",
                ride
            });
        } catch (error) {
            console.error(
                "BOOK RIDE ERROR:",
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

async function getDriverAvailableRides(req, res) {
    try {
        const rides = await Ride.find({
            status: "Searching for driver",
            driverId: null,
            $or: [
                {
                    assignedDriverId:
                        req.user._id
                },
                {
                    assignedDriverId: null
                },
                {
                    assignedDriverId:
                        { $exists: false }
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
            rides
        });
    } catch (error) {
        console.error(
            "DRIVER RIDES ERROR:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to load rides.",
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
   ALL RIDES COMPATIBILITY
========================================================= */

app.get(
    "/api/rides",
    authenticate,
    async (req, res) => {
        try {
            let filter = {};

            if (req.user.role === "passenger") {
                filter = {
                    userId: req.user._id
                };
            } else if (req.user.role === "driver") {
                filter = {
                    status:
                        "Searching for driver",
                    driverId: null,
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
                                { $exists: false }
                        }
                    ]
                };
            }

            const rides =
                await Ride.find(filter)
                    .populate(
                        "userId",
                        "name email city"
                    )
                    .populate(
                        "driverId",
                        "name email vehicleNumber vehicleType rating location online blocked"
                    )
                    .sort({
                        createdAt: -1
                    });

            res.json({
                success: true,
                rides
            });
        } catch (error) {
            console.error(
                "GET RIDES ERROR:",
                error
            );

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
   DRIVER ACCEPT RIDE
========================================================= */

app.post(
    "/api/rides/:id/accept",
    authenticate,
    requireRole("driver"),
    async (req, res) => {
        try {
            if (req.user.blocked) {
                return res.status(403).json({
                    success: false,
                    blocked: true,
                    message:
                        "🚫 Driver is blocked."
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

            if (ride.driverId) {
                return res.status(409).json({
                    success: false,
                    message:
                        "Ride already accepted."
                });
            }

            if (
                ride.status !==
                "Searching for driver"
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

            return res.json({
                success: true,
                message:
                    "🚕 Ride accepted successfully!",
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
                    "Unable to accept ride."
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

/* =========================================================
   PARCEL REQUESTS
========================================================= */

app.get(
    "/api/driver/:id/requests",
    authenticate,
    requireRole("driver"),
    async (req, res) => {
        try {
            if (
                String(req.params.id) !==
                String(req.user._id)
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

                    $or: [
                        {
                            assignedDriverId:
                                req.user._id
                        },
                        {
                            driverId:
                                req.user._id
                        }
                    ],

                    status: {
                        $nin: [
                            "Completed",
                            "Cancelled"
                        ]
                    }
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

            const isPassenger =
                ride.userId &&
                String(
                    ride.userId._id
                ) ===
                    String(req.user._id);

            const isDriver =
                ride.driverId &&
                String(
                    ride.driverId._id
                ) ===
                    String(req.user._id);

            const isAdmin =
                req.user.role ===
                "admin";

            if (
                !isPassenger &&
                !isDriver &&
                !isAdmin
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

/* =========================================================
   START RIDE
========================================================= */

async function startRide(req, res) {
    try {
        const ride =
            await Ride.findOne({
                _id: req.params.id,
                driverId: req.user._id
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

app.patch(
    "/api/rides/:id/start",
    authenticate,
    requireRole("driver"),
    startRide
);

app.post(
    "/api/rides/:id/start",
    authenticate,
    requireRole("driver"),
    startRide
);

/* =========================================================
   COMPLETE RIDE
========================================================= */

async function completeRide(req, res) {
    try {
        const ride =
            await Ride.findOne({
                _id: req.params.id,
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

app.patch(
    "/api/rides/:id/complete",
    authenticate,
    requireRole("driver"),
    completeRide
);

app.post(
    "/api/rides/:id/complete",
    authenticate,
    requireRole("driver"),
    completeRide
);

/* =========================================================
   CANCEL RIDE
========================================================= */

async function cancelRide(req, res) {
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

app.patch(
    "/api/rides/:id/cancel",
    authenticate,
    cancelRide
);

app.post(
    "/api/rides/:id/cancel",
    authenticate,
    cancelRide
);

/* =========================================================
   PASSENGER LOCATION
========================================================= */

async function updatePassengerLocation(req, res) {
    try {
        const lat = numberOrNull(
            req.body.latitude ??
            req.body.lat
        );

        const lng = numberOrNull(
            req.body.longitude ??
            req.body.lng
        );

        const accuracy = numberOrNull(
            req.body.accuracy
        );

        if (lat === null || lng === null) {
            return res.status(400).json({
                success: false,
                message:
                    "Invalid location."
            });
        }

        const ride =
            await Ride.findOne({
                _id: req.params.id,
                userId: req.user._id
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
            updatedAt: new Date()
        };

        await ride.save();

        req.user.location = {
            lat,
            lng,
            accuracy,
            updatedAt: new Date()
        };

        await req.user.save();

        res.json({
            success: true,
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

app.patch(
    "/api/rides/:id/passenger-location",
    authenticate,
    requireRole("passenger"),
    updatePassengerLocation
);

app.post(
    "/api/rides/:id/location",
    authenticate,
    requireRole("passenger"),
    updatePassengerLocation
);

/* =========================================================
   DRIVER LOCATION
========================================================= */

async function updateDriverLocation(req, res) {
    try {
        const lat = numberOrNull(
            req.body.latitude ??
            req.body.lat
        );

        const lng = numberOrNull(
            req.body.longitude ??
            req.body.lng
        );

        const accuracy = numberOrNull(
            req.body.accuracy
        );

        if (lat === null || lng === null) {
            return res.status(400).json({
                success: false,
                message:
                    "Invalid location."
            });
        }

        const ride =
            await Ride.findOne({
                _id: req.params.id,
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

        const location = {
            lat,
            lng,
            accuracy,
            updatedAt: new Date()
        };

        ride.driverLocation =
            location;

        await ride.save();

        req.user.location =
            location;

        req.user.online = true;

        await req.user.save();

        res.json({
            success: true,
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

app.patch(
    "/api/rides/:id/driver-location",
    authenticate,
    requireRole("driver"),
    updateDriverLocation
);

app.post(
    "/api/rides/:id/driver-location",
    authenticate,
    requireRole("driver"),
    updateDriverLocation
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
                rides
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message:
                    "Unable to load your rides.",
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
                        createdAt: -1
                    })
                    .lean();

            res.json({
                success: true,
                passengers
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message:
                    "Unable to load passengers.",
                passengers: []
            });
        }
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
        try {
            const drivers =
                await User.find({
                    role:
                        "driver"
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
        } catch (error) {
            res.status(500).json({
                success: false,
                message:
                    "Unable to load drivers.",
                drivers: []
            });
        }
    }
);

/* =========================================================
   ADMIN - BLOCK DRIVER
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
                        new: true
                    }
                )
                    .select("-password")
                    .lean();

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

/* =========================================================
   ADMIN - UNBLOCK DRIVER
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
                        new: true
                    }
                )
                    .select("-password")
                    .lean();

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
                success: true,
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

/* =========================================================
   ADMIN - USERS
========================================================= */

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
                        createdAt: -1
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

/* =========================================================
   ADMIN - RIDES
========================================================= */

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
                        createdAt: -1
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
            ] = await Promise.all([
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
   ADMIN LIVE LOCATIONS
========================================================= */

app.get(
    "/api/live-locations",
    authenticate,
    requireRole("admin"),
    async (req, res) => {
        try {
            const activeRides =
                await Ride.find({
                    status: {
                        $nin: [
                            "Completed",
                            "Cancelled"
                        ]
                    }
                }).lean();

            const locations =
                activeRides.map(
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
                success: true,
                serviceArea:
                    "Nalanda",
                locations
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message:
                    "Unable to load live locations.",
                locations: []
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
                    name:
                        "Nalanda",
                    active:
                        true
                }
            ]
        });
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
            message:
                "UDAN CAB server is running.",
            database:
                mongoose.connection.readyState === 1
                    ? "connected"
                    : "connecting/disconnected",
            time:
                new Date().toISOString()
        });
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
                "Internal server error.",
            error:
                error.message
        });
    }
);

/* =========================================================
   START SERVER
========================================================= */

app.listen(
    PORT,
    () => {
        console.log("");
        console.log(
            "=========================================="
        );
        console.log(
            `🚕 UDAN CAB SERVER RUNNING ON PORT ${PORT}`
        );
        console.log(
            "=========================================="
        );
        console.log(
            "✅ MongoDB"
        );
        console.log(
            "✅ Login / Register"
        );
        console.log(
            "✅ OTP / Password Reset"
        );
        console.log(
            "✅ Passenger"
        );
        console.log(
            "✅ Driver"
        );
        console.log(
            "✅ Ride Booking"
        );
        console.log(
            "✅ Parcel"
        );
        console.log(
            "✅ GPS / Live Location"
        );
        console.log(
            "✅ Admin"
        );
        console.log(
            "✅ Block / Unblock / Remove Driver"
        );
        console.log(
            "✅ Frontend Serving"
        );
        console.log(
            "=========================================="
        );
        console.log("");
    }
);
