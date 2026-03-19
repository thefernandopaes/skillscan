import fetch from "node-fetch";

const API_BASE = "https://api.openweathermap.org/data/2.5";

interface WeatherResponse {
	temperature: number;
	description: string;
	city: string;
}

export async function getWeather(city: string): Promise<WeatherResponse> {
	const apiKey = process.env.OPENWEATHER_API_KEY;
	const response = await fetch(`${API_BASE}/weather?q=${encodeURIComponent(city)}&appid=${apiKey}`);
	const data = (await response.json()) as Record<string, unknown>;

	return {
		temperature: (data as Record<string, unknown>).temp as number,
		description: (data as Record<string, unknown>).description as string,
		city,
	};
}
