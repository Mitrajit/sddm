import axios from "axios";

export const googleDnsService = axios.create({
    baseURL: "https://dns.google",
    method: "GET",
    headers: {
        "Content-Type": "application/json",
        Accept: "application/dns-json",
    },
});
