#version 300 es

#ifdef GL_ES
precision highp float;
precision highp int;
#endif

uniform sampler2D image;
uniform ivec2 u_in_size;
uniform ivec2 u_logical_size;
uniform ivec4 u_layout;
uniform ivec4 u_content;

in vec2 tex;
layout(location = 0) out float color;

int floorDiv2(int v)
{
	return (v >= 0) ? (v >> 1) : -((-v + 1) >> 1);
}

void main()
{
	int dx = int(gl_FragCoord.x);
	int dy = int(gl_FragCoord.y);

	int logical_w = u_logical_size.x;
	int logical_h = u_logical_size.y;
	int tile_w = u_layout.x;
	int split_x = u_layout.y;
	int tile_h = u_layout.z;

	int sx = 0;
	int sy = 0;
	int channel = 0;

	if (dx < tile_w) {
		sx = min(dx, logical_w - 1);
		if (dy < tile_h) {
			sy = min(dy, logical_h - 1);
			channel = 0;
		} else {
			sy = min(dy - tile_h, logical_h - 1);
			channel = 1;
		}
	} else {
		int rx = dx - tile_w;
		if (dy < tile_h) {
			sx = min(rx, split_x - 1);
			sy = min(dy, logical_h - 1);
		} else {
			sx = min(split_x + rx, logical_w - 1);
			sy = min(dy - tile_h, logical_h - 1);
		}
		channel = 2;
	}

	sx = clamp(sx, 0, logical_w - 1);
	sy = clamp(sy, 0, logical_h - 1);

	vec3 rgb = vec3(0.0);
	if (sx >= u_content.x && sx < u_content.x + u_content.z &&
	    sy >= u_content.y && sy < u_content.y + u_content.w) {
		if (u_content.xy == ivec2(0) && u_content.zw == u_in_size) {
			rgb = texelFetch(image, ivec2(sx, sy), 0).rgb;
		} else {
			vec2 uv = (vec2(sx - u_content.x, sy - u_content.y) + 0.5) / vec2(u_content.zw);
			rgb = texture(image, uv).rgb;
		}
	}

	ivec3 c = ivec3(round(clamp(rgb, 0.0, 1.0) * 255.0));
	int co = c.r - c.b;
	int t = c.b + floorDiv2(co);
	int cg = c.g - t;
	int y = t + floorDiv2(cg);

	int val10 = 0;
	if (channel == 0) {
		val10 = 4 * y;
	} else if (channel == 1) {
		val10 = 512 + 2 * co;
	} else {
		val10 = 512 + 2 * cg;
	}

	color = float(val10 * 64) / 65535.0;
}
