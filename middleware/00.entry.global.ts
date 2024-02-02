// import { useFrontendStore } from "../stores/frontend";

const USER_ALLOWED = "YES";
const API_BASE_URL = "https://taxotool-dev.voeb-service.de/modules";
const AUTH_HEADER = new Headers({
    Authorization: `Basic ${btoa("dydon:staging")}`,
    "Content-Type": "application/x-www-form-urlencoded",
});

interface JWTResponse {
    decodedJWT: boolean;
    [key: string]: any;
}

interface Entry {
    taskID?: string | null;
    actionKey?: string | null;
    Bankenportaltoken?: string | null;
    userMail?: string | null;
    jwtFrontEnd?: string | null;
}

async function validateJWT(jwt: string): Promise<JWTResponse> {
    const endpoint = `${API_BASE_URL}/indexValidateJWTHelper.php`;
    return await $fetch(endpoint, {
        method: "POST",
        headers: AUTH_HEADER,
        body: new URLSearchParams({ jwt }),
    });
}

export default defineNuxtRouteMiddleware(async (to, from) => {
    const frontendStore = {} || useFrontendStore();
    if (useIsClientSide()) {
        try {
            // This flags helps to know whether the User is authenticated to access the route
            // If not authenticated then it will recheck the Token Existence and Validation of Token if anywhere it fails will redirect to Error Page.
            if (!frontendStore.isAuthenticated) {
                //  If JWT Is available in store then validate 
                if (frontendStore.entry.jwtFrontEnd) {
                    const validatedJWTData: JWTResponse = await validateJWT(
                        frontendStore.entry.jwtFrontEnd
                    );
                    if (!validatedJWTData || validatedJWTData.decodedJWT === false) {
                        throw createError({
                            statusCode: 403,
                            statusMessage: "Forbidden",
                            fatal: true,
                        });
                    } else {
                        frontendStore.entrySyncToLocalStorage();
                    }
                } else {
                    //  If Token is not available in store then extract from LocalStorage and Validate
                    const storedEntryString = localStorage.getItem("entry");
                    if (storedEntryString) {
                        const storedEntry: Entry = JSON.parse(storedEntryString);
                        if (storedEntry.jwtFrontEnd) {
                            const validatedJWTData: JWTResponse = await validateJWT(
                                storedEntry.jwtFrontEnd
                            );
                            if (!validatedJWTData || validatedJWTData.decodedJWT === false) {
                                //  If Token not validated then throw Error and in Catch will redirect to ErrorPage.
                                throw createError({
                                    statusCode: 403,
                                    statusMessage: "Forbidden",
                                    fatal: true,
                                });
                            } else {
                                // If token Validated then Reset The Store.
                                frontendStore.entrySet(storedEntry);
                                frontendStore.userSet(validatedJWTData.decodedJWT);
                            }
                        } else {
                            //  If Token not available in localStorage Either two things can be done Return to Login Page or Redirect to Error Page.
                            //  Currently I am redirecting to ErrorPage as mentioned in task Requirement.
                            throw createError({
                                statusCode: 403,
                                statusMessage: "Forbidden",
                                fatal: true,
                            });
                        }
                    } else {
                        // This is same case where Entry Object itself is not present in LocalStorage and same thing can be done in respect to the use cases.
                        // Currently considering the redirection as default to ErrorPage so doing same by throwing error and in catch redirecting to ErrorPage.
                        throw createError({
                            statusCode: 403,
                            statusMessage: "Forbidden",
                            fatal: true,
                        });
                    }
                }
            } else {
                // If all good and User is Authenticated then Proceed Further to next Middleware
                return;
            }
        } catch (error) {
            if (to.path !== '/error-page')
                // handling all errors in this Try...Catch Blocks and default redirection for every error on ErrroPage.
                return navigateTo('/error-page')
        }
    }
    if (useIsServerSide()) {
        try {
            const { query } = to;
            const parameters: Entry = {
                taskID: null,
                actionKey: null,
                Bankenportaltoken: null,
            };

            Object.keys(query).forEach((key) => {
                if (key in parameters) {
                    const value = query[key];
                    parameters[key as keyof Entry] = Array.isArray(value)
                        ? value[0]
                        : value;
                }
            });
            if (Object.values(parameters).some((value) => value)) {
                const data: any = await $fetch(`${API_BASE_URL}/index2.php`, {
                    headers: AUTH_HEADER,
                    params: parameters,
                });

                const response = JSON.parse(data);

                if (response.userAllowed !== USER_ALLOWED) {
                    // Redirect unauthenticated users to the error page
                    throw new Error("Unauthorized");
                } else {
                    const validatedJWTData: JWTResponse = await validateJWT(
                        response.jwtFrontEnd)
                    if (!validatedJWTData || validatedJWTData.decodedJWT === false) {
                        // Redirect unauthenticated users to the error page
                        throw new Error("Unauthorized");
                    } else {
                        frontendStore.entrySet({
                            ...parameters,
                            userMail: response.userMail,
                            jwtFrontEnd: response.jwtFrontEnd,
                        });
                        frontendStore.userSet(validatedJWTData.decodedJWT);
                    }
                }
            } else {
                // Redirect users without URL parameters to the error page
                console.log("User entered without URL params");
                throw createError({
                    statusCode: 400,
                    statusMessage: "Bad Request",
                    fatal: true,
                });
            }
        } catch (error) {
            //  Here I added Try Catch Block inorder to add default redirection for serverSide to ErrorPage for all errors.

        }
    }
});
