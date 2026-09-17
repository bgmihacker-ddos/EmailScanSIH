/// <reference types="vite/client" />

interface ImportMetaEnv {
	readonly VITE_API_URL?: string;
	readonly VITE_GEOAPIFY_API_KEY?: string;
	readonly VITE_DEV_BYPASS_AUTH?: string;
	readonly VITE_GOOGLE_CLIENT_ID?: string;
}

interface ImportMeta {
	readonly env: ImportMetaEnv;
}

declare module 'world-atlas/countries-110m.json' {
	const worldAtlas: { objects: { countries: unknown } };
	export default worldAtlas;
}
