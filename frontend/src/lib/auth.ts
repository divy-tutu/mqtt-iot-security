const KEY = "homepulse-logged-in";

export const isLoggedIn = () => sessionStorage.getItem(KEY) === "1";

export const login = () => sessionStorage.setItem(KEY, "1");

export const logout = () => sessionStorage.removeItem(KEY);
