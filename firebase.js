// ScamLens Firebase services (Firebase JS SDK 11.10.0)

import { initializeApp } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js";

import {
    getFirestore,
    collection,
    doc,
    setDoc,
    getDocs,
    deleteDoc
} from "https://www.gstatic.com/firebasejs/11.10.0/firebase-firestore.js";

import { getAuth } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js";

export function initializeScamLensFirebase(firebaseConfig) {
    const app = initializeApp(firebaseConfig);
    const auth = getAuth(app);
    const db = getFirestore(app);

    function scansCollection(uid) {
        return collection(db, "users", uid, "scans");
    }

    function watchlistCollection(uid) {
        return collection(db, "users", uid, "watchlist");
    }

    async function loadWatchlist() {
        const user = auth.currentUser;

        if (!user) {
            return [];
        }

        const snapshot = await getDocs(
            watchlistCollection(user.uid)
        );

        return snapshot.docs
            .map((item) => ({
                ...item.data(),
                id: item.id
            }))
            .sort((a, b) =>
                String(a.domain || "").localeCompare(
                    String(b.domain || "")
                )
            );
    }

    async function addWatchlistDomain(domain) {
        const user = auth.currentUser;

        if (!user) {
            throw new Error(
                "Sign in before adding a domain to your watchlist."
            );
        }

        const normalized = String(domain || "")
            .trim()
            .toLowerCase()
            .replace(/^www\./, "");

        if (
            !normalized ||
            normalized.length > 253 ||
            !normalized.includes(".") ||
            /[\s/:?#@]/.test(normalized)
        ) {
            throw new Error(
                "Enter a valid domain name, such as example.com."
            );
        }

        const existing = await loadWatchlist();

        if (existing.some((item) => item.domain === normalized)) {
            throw new Error(
                "That domain is already on your watchlist."
            );
        }

        const reference = doc(
            watchlistCollection(user.uid)
        );

        const entry = {
            domain: normalized,
            addedAt: new Date().toISOString()
        };

        await setDoc(reference, entry);

        return {
            ...entry,
            id: reference.id
        };
    }

    async function removeWatchlistDomain(domainId) {
        const user = auth.currentUser;

        if (!user) {
            throw new Error(
                "Sign in before editing your watchlist."
            );
        }

        if (!domainId || typeof domainId !== "string") {
            throw new Error("Invalid watchlist item.");
        }

        await deleteDoc(
            doc(db, "users", user.uid, "watchlist", domainId)
        );
    }

    async function loadHistory() {
        const user = auth.currentUser;

        if (!user) {
            return [];
        }

        const snapshot = await getDocs(
            scansCollection(user.uid)
        );

        return snapshot.docs
            .map((item) => ({
                ...item.data(),
                id: item.id
            }))
            .sort(
                (a, b) =>
                    new Date(b.scannedAt || 0).getTime() -
                    new Date(a.scannedAt || 0).getTime()
            )
            .slice(0, 20);
    }

    async function saveScan(entry) {
        const user = auth.currentUser;

        if (!user) {
            throw new Error(
                "Sign in before saving scan history."
            );
        }

        const reference = doc(scansCollection(user.uid));

        await setDoc(reference, {
            url: String(entry.url || ""),
            score: Number(entry.score) || 0,
            riskLabel: String(
                entry.riskLabel || "Assessment unavailable"
            ),
            scannedAt: String(
                entry.scannedAt || new Date().toISOString()
            )
        });

        return {
            ...entry,
            id: reference.id
        };
    }

    async function deleteScan(scanId) {
        const user = auth.currentUser;

        if (!user) {
            throw new Error("You must be signed in.");
        }

        if (!scanId || typeof scanId !== "string") {
            throw new Error("Invalid scan ID.");
        }

        await deleteDoc(
            doc(db, "users", user.uid, "scans", scanId)
        );
    }

    async function clearHistory() {
        const user = auth.currentUser;

        if (!user) {
            throw new Error("You must be signed in.");
        }

        const snapshot = await getDocs(
            scansCollection(user.uid)
        );

        await Promise.all(
            snapshot.docs.map((item) => deleteDoc(item.ref))
        );
    }

    return {
        auth,
        db,
        loadHistory,
        saveScan,
        deleteScan,
        clearHistory,
        loadWatchlist,
        addWatchlistDomain,
        removeWatchlistDomain
    };
}