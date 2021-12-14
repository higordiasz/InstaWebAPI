using System;

namespace InstaWebAPI.Webhelper
{
    internal static class WebHelper
    {
        const string StartTag = "type=\"text/javascript\">window._sharedData";
        const string EndTag = ";</script>";
        public static bool CanReadJson(this string html)
        {
            return html.Contains(StartTag);
        }
        public static string GetJson(this string html)
        {
            try
            {
                if (html.CanReadJson())
                {
                    var json = html.Substring(html.IndexOf(StartTag) + StartTag.Length);
                    json = json.Substring(0, json.IndexOf(EndTag));
                    json = json.Substring(json.IndexOf("=") + 2);
                    return json;
                }
            }
            catch (Exception ex) { Console.WriteLine($"WebHelper.GetJson ex: {ex.Message}\r\nSource: {ex.Source}\r\nTrace: {ex.StackTrace}"); }
            return null;
        }
    }
}
