import sqlite3

def fix_image_paths():
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect('joone.db')
        cursor = conn.cursor()

        # Update the image paths by removing the 'static/' prefix
        cursor.execute("""
            UPDATE products 
            SET image = REPLACE(image, 'static/', '')
            WHERE image LIKE 'static/%'
        """)

        # Commit the changes
        conn.commit()

        # Debug: Show updated product images
        cursor.execute("SELECT id, name, image FROM products")
        products = cursor.fetchall()
        print("Updated product images:")
        for product in products:
            print(product)

    except sqlite3.Error as e:
        print(f"An error occurred with the SQLite database: {e}")
    
    finally:
        # Ensure the connection is closed
        conn.close()

if __name__ == "__main__":
    fix_image_paths()